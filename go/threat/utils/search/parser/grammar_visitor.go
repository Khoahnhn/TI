// Code generated from Grammar.g4 by ANTLR 4.8. DO NOT EDIT.

package parser // Grammar

import "github.com/antlr/antlr4/runtime/Go/antlr"

// A complete Visitor for a parse tree produced by GrammarParser.
type GrammarVisitor interface {
	antlr.ParseTreeVisitor

	// Visit a parse tree produced by GrammarParser#prog.
	VisitProg(ctx *ProgContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareNumber.
	VisitCompareNumber(ctx *CompareNumberContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareString.
	VisitCompareString(ctx *CompareStringContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareDate.
	VisitCompareDate(ctx *CompareDateContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareBoolean.
	VisitCompareBoolean(ctx *CompareBooleanContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareSeverity.
	VisitCompareSeverity(ctx *CompareSeverityContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareStatus.
	VisitCompareStatus(ctx *CompareStatusContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareCategory.
	VisitCompareCategory(ctx *CompareCategoryContext) interface{}

	// Visit a parse tree produced by GrammarParser#compareFeature.
	VisitCompareFeature(ctx *CompareFeatureContext) interface{}

	// Visit a parse tree produced by GrammarParser#expression.
	VisitExpression(ctx *ExpressionContext) interface{}
}
