package search

import (
	"strconv"
	"strings"

	"github.com/antlr/antlr4/runtime/Go/antlr"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/utils/search/parser"
)

type grammarVisitor struct {
	antlr.ParseTreeVisitor
	Query grammarQuery
}

func (v *grammarVisitor) Visit(tree antlr.ParseTree) interface{} {
	return tree.Accept(v)
}

func (v *grammarVisitor) VisitProg(ctx *parser.ProgContext) interface{} {
	return ctx.Expression().Accept(v)
}

func (v *grammarVisitor) VisitCompareNumber(ctx *parser.CompareNumberContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		return v.Query.QueryNumber(op.GetText(), ctx.GetLeft().GetText(), strings.Trim(ctx.GetRight().GetText(), "\""))
	}

	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareString(ctx *parser.CompareStringContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		return v.Query.QueryString(op.GetText(), ctx.GetLeft().GetText(), strings.Trim(ctx.GetRight().GetText(), "'"))
	}

	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareDate(ctx *parser.CompareDateContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		return v.Query.QueryNumber(op.GetText(), ctx.GetLeft().GetText(), ctx.GetRight().GetText())
	}
	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareBoolean(ctx *parser.CompareBooleanContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		value, err := strconv.ParseBool(ctx.GetRight().GetText())
		if err == nil {
			return v.Query.QueryBoolean(op.GetText(), ctx.GetLeft().GetText(), value)
		}
	}

	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareSeverity(ctx *parser.CompareSeverityContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		right := ctx.GetRight()
		severity := 0
		if right.GetText() == "low" {
			severity = 0
		} else if right.GetText() == "medium" {
			severity = 1
		} else if right.GetText() == "high" {
			severity = 2
		} else if right.GetText() == "critical" {
			severity = 3
		}

		return v.Query.QueryNumber(op.GetText(), ctx.GetLeft().GetText(), severity)
	}
	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareStatus(ctx *parser.CompareStatusContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		right := ctx.GetRight()
		status := 0
		if right.GetText() == "closed" {
			status = 1
		} else if right.GetText() == "false_positive" {
			status = -1
		}

		return v.Query.QueryNumber(op.GetText(), ctx.GetLeft().GetText(), status)
	}
	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareCategory(ctx *parser.CompareCategoryContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		right := ctx.GetRight()
		category := ""
		switch right.GetText() {
		case "open_port_anomaly":
			category = defs.PortAnomaly
		default:
			category = right.GetText()
		}
		return v.Query.QueryString(op.GetText(), "cats", category)
	}
	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitCompareFeature(ctx *parser.CompareFeatureContext) interface{} {
	if op := ctx.GetOp(); op != nil {
		right := ctx.GetRight()
		source := ""
		switch right.GetText() {
		case "brand_abuse":
			source = defs.ImpersonateBrand
		case "malware_apt":
			source = defs.Malware
		default:
			source = right.GetText()
		}

		return v.Query.QueryString(op.GetText(), "source", source)
	}
	return v.VisitChildren(ctx)
}

func (v *grammarVisitor) VisitExpression(ctx *parser.ExpressionContext) interface{} {

	if op := ctx.GetOp(); op != nil {
		left := ctx.GetLeft()
		right := ctx.GetRight()

		leftResult := left.Accept(v)
		rightResult := right.Accept(v)

		if op.GetText() == "AND" {
			return map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						leftResult,
						rightResult,
					},
				},
			}
		}

		if op.GetText() == "OR" {
			return map[string]interface{}{
				"bool": map[string]interface{}{
					"should": []interface{}{
						leftResult,
						rightResult,
					},
				},
			}
		}

		return map[string]interface{}{
			"match_all": map[string]interface{}{},
		}
	}

	if express := ctx.GetInner(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareString(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareStatus(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareDate(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareNumber(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareSeverity(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareBoolean(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareCategory(); express != nil {
		return express.Accept(v)
	}
	if express := ctx.CompareFeature(); express != nil {
		return express.Accept(v)
	}

	return nil
}
