"""Safe expression evaluator.

Use instead of `eval()` in MCP tools that need to accept a user-supplied
arithmetic/logical expression (calculator-style, conditional formulas,
threshold rules). Allows only a fixed set of AST nodes — no attribute
access, no subscripts on arbitrary objects, no function calls except a
small whitelist of pure builtins.

This is NOT a general-purpose Python sandbox. It is the simplest correct
evaluator for expressions like `2 * x + min(y, 10)`. Anything more
complex should be done by parsing your own DSL or by using
`asteval` / `simpleeval` — both are well-audited libraries.
"""

from __future__ import annotations

import ast
import operator
from typing import Any


class UnsafeExpression(ValueError):
    """The expression contains an AST node that the evaluator refuses."""


_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Not: operator.not_,
}

_BOOL_OPS = {
    ast.And: all,
    ast.Or: any,
}

_CMP_OPS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}

# Whitelist of safe pure builtins that may appear as `f(args)`.
_SAFE_CALLS = {
    "abs": abs,
    "min": min,
    "max": max,
    "round": round,
    "len": len,
    "int": int,
    "float": float,
    "bool": bool,
    "sum": sum,
}

# Hard cap on `**` exponent to prevent CPU/memory DoS via `9 ** 9999999`.
_MAX_POW_EXPONENT = 1024


def _eval(node: ast.AST, variables: dict[str, Any]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, variables)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, int | float | bool | str) or node.value is None:
            return node.value
        raise UnsafeExpression(f"constant of type {type(node.value).__name__} not allowed")

    if isinstance(node, ast.Name):
        if node.id in variables:
            return variables[node.id]
        raise UnsafeExpression(f"unknown name {node.id!r}")

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _BIN_OPS:
            raise UnsafeExpression(f"binary op {op_type.__name__} not allowed")
        left = _eval(node.left, variables)
        right = _eval(node.right, variables)
        if op_type is ast.Pow and isinstance(right, int | float) and right > _MAX_POW_EXPONENT:
            raise UnsafeExpression(
                f"exponent {right} exceeds maximum {_MAX_POW_EXPONENT} (DoS guard)"
            )
        return _BIN_OPS[op_type](left, right)

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _UNARY_OPS:
            raise UnsafeExpression(f"unary op {op_type.__name__} not allowed")
        return _UNARY_OPS[op_type](_eval(node.operand, variables))

    if isinstance(node, ast.BoolOp):
        op_type = type(node.op)
        if op_type not in _BOOL_OPS:
            raise UnsafeExpression(f"bool op {op_type.__name__} not allowed")
        return _BOOL_OPS[op_type](_eval(v, variables) for v in node.values)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, variables)
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            op_type = type(op)
            if op_type not in _CMP_OPS:
                raise UnsafeExpression(f"comparison op {op_type.__name__} not allowed")
            right = _eval(comparator, variables)
            if not _CMP_OPS[op_type](left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.IfExp):
        return _eval(node.body, variables) if _eval(node.test, variables) else _eval(node.orelse, variables)

    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name) or node.func.id not in _SAFE_CALLS:
            name = getattr(node.func, "id", type(node.func).__name__)
            raise UnsafeExpression(f"call to {name!r} not allowed")
        if node.keywords:
            raise UnsafeExpression("keyword arguments not allowed")
        args = [_eval(a, variables) for a in node.args]
        return _SAFE_CALLS[node.func.id](*args)

    raise UnsafeExpression(f"node of type {type(node).__name__} not allowed")


def evaluate_expression(
    expr: str,
    *,
    variables: dict[str, Any] | None = None,
    max_length: int = 1024,
) -> Any:
    """Safely evaluate `expr` against an optional `variables` mapping.

    Allowed:
        * literals: int, float, bool, str, None
        * binary ops: + - * / // % **  (`**` exponent capped at 1024)
        * unary ops: +x  -x  not x
        * boolean ops: and, or
        * comparisons: ==  !=  <  <=  >  >=
        * ternary: `a if cond else b`
        * variable names that are keys of `variables`
        * calls to: abs, min, max, round, len, int, float, bool, sum

    Refused:
        * attribute access, subscripts, slices, comprehensions
        * lambdas, function/class defs, imports, assignments
        * any call other than the whitelist above
        * unknown variable names

    Args:
        expr: Expression source.
        variables: Mapping of name → value made available to the
            expression. Default empty.
        max_length: Reject expressions longer than this. Default 1024.

    Returns:
        The result of evaluation.

    Raises:
        UnsafeExpression: malformed source or any disallowed AST node.

    Example:
        >>> from mcp_security_toolkit.helpers import evaluate_expression
        >>> evaluate_expression("price * (1 - discount)", variables={"price": 100, "discount": 0.1})
        90.0
    """
    if not isinstance(expr, str):
        raise UnsafeExpression("expression must be a string")
    if len(expr) > max_length:
        raise UnsafeExpression(f"expression length {len(expr)} exceeds max {max_length}")

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as e:
        raise UnsafeExpression(f"syntax error: {e.msg}") from e

    return _eval(tree, variables or {})
