// Code generated from Grammar.g4 by ANTLR 4.8. DO NOT EDIT.

package parser // Grammar

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/antlr/antlr4/runtime/Go/antlr"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = reflect.Copy
var _ = strconv.Itoa

var parserATN = []uint16{
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 3, 55, 80, 4,
	2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7, 9, 7, 4,
	8, 9, 8, 4, 9, 9, 9, 4, 10, 9, 10, 4, 11, 9, 11, 3, 2, 3, 2, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 4, 3, 4, 3, 4, 3, 4, 3, 5, 3, 5, 3, 5, 3, 5, 3, 6, 3, 6,
	3, 6, 3, 6, 3, 7, 3, 7, 3, 7, 3, 7, 3, 8, 3, 8, 3, 8, 3, 8, 3, 9, 3, 9,
	3, 9, 3, 9, 3, 10, 3, 10, 3, 10, 3, 10, 3, 11, 3, 11, 3, 11, 3, 11, 3,
	11, 3, 11, 3, 11, 3, 11, 3, 11, 3, 11, 3, 11, 3, 11, 3, 11, 5, 11, 70,
	10, 11, 3, 11, 3, 11, 3, 11, 7, 11, 75, 10, 11, 12, 11, 14, 11, 78, 11,
	11, 3, 11, 2, 3, 20, 12, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 2, 6, 3, 2,
	35, 36, 3, 2, 34, 35, 3, 2, 7, 16, 6, 2, 7, 8, 12, 12, 14, 14, 18, 19,
	2, 78, 2, 22, 3, 2, 2, 2, 4, 24, 3, 2, 2, 2, 6, 28, 3, 2, 2, 2, 8, 32,
	3, 2, 2, 2, 10, 36, 3, 2, 2, 2, 12, 40, 3, 2, 2, 2, 14, 44, 3, 2, 2, 2,
	16, 48, 3, 2, 2, 2, 18, 52, 3, 2, 2, 2, 20, 69, 3, 2, 2, 2, 22, 23, 5,
	20, 11, 2, 23, 3, 3, 2, 2, 2, 24, 25, 7, 33, 2, 2, 25, 26, 9, 2, 2, 2,
	26, 27, 7, 22, 2, 2, 27, 5, 3, 2, 2, 2, 28, 29, 7, 32, 2, 2, 29, 30, 9,
	3, 2, 2, 30, 31, 7, 23, 2, 2, 31, 7, 3, 2, 2, 2, 32, 33, 7, 3, 2, 2, 33,
	34, 9, 2, 2, 2, 34, 35, 7, 23, 2, 2, 35, 9, 3, 2, 2, 2, 36, 37, 7, 31,
	2, 2, 37, 38, 7, 35, 2, 2, 38, 39, 7, 27, 2, 2, 39, 11, 3, 2, 2, 2, 40,
	41, 7, 4, 2, 2, 41, 42, 7, 35, 2, 2, 42, 43, 7, 45, 2, 2, 43, 13, 3, 2,
	2, 2, 44, 45, 7, 5, 2, 2, 45, 46, 7, 35, 2, 2, 46, 47, 7, 46, 2, 2, 47,
	15, 3, 2, 2, 2, 48, 49, 7, 6, 2, 2, 49, 50, 7, 35, 2, 2, 50, 51, 9, 4,
	2, 2, 51, 17, 3, 2, 2, 2, 52, 53, 7, 17, 2, 2, 53, 54, 7, 35, 2, 2, 54,
	55, 9, 5, 2, 2, 55, 19, 3, 2, 2, 2, 56, 57, 8, 11, 1, 2, 57, 58, 7, 20,
	2, 2, 58, 59, 5, 20, 11, 2, 59, 60, 7, 21, 2, 2, 60, 70, 3, 2, 2, 2, 61,
	70, 5, 4, 3, 2, 62, 70, 5, 6, 4, 2, 63, 70, 5, 12, 7, 2, 64, 70, 5, 8,
	5, 2, 65, 70, 5, 14, 8, 2, 66, 70, 5, 10, 6, 2, 67, 70, 5, 16, 9, 2, 68,
	70, 5, 18, 10, 2, 69, 56, 3, 2, 2, 2, 69, 61, 3, 2, 2, 2, 69, 62, 3, 2,
	2, 2, 69, 63, 3, 2, 2, 2, 69, 64, 3, 2, 2, 2, 69, 65, 3, 2, 2, 2, 69, 66,
	3, 2, 2, 2, 69, 67, 3, 2, 2, 2, 69, 68, 3, 2, 2, 2, 70, 76, 3, 2, 2, 2,
	71, 72, 12, 12, 2, 2, 72, 73, 7, 24, 2, 2, 73, 75, 5, 20, 11, 13, 74, 71,
	3, 2, 2, 2, 75, 78, 3, 2, 2, 2, 76, 74, 3, 2, 2, 2, 76, 77, 3, 2, 2, 2,
	77, 21, 3, 2, 2, 2, 78, 76, 3, 2, 2, 2, 4, 69, 76,
}
var deserializer = antlr.NewATNDeserializer(nil)
var deserializedATN = deserializer.DeserializeFromUInt16(parserATN)

var literalNames = []string{
	"", "'created_date'", "'severity'", "'status'", "'category'", "'vulnerability'",
	"'malware'", "'impersonate'", "'phishing'", "'impersonate_social'", "'targeted_vulnerability'",
	"'open_port_anomaly'", "'compromised_system'", "'deface_attack'", "'leak'",
	"'feature'", "'brand_abuse'", "'data_leakage'", "'('", "')'", "", "", "",
	"'AND'", "'OR'", "", "'true'", "'false'", "", "'private'", "", "", "",
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "'NULL'",
}
var symbolicNames = []string{
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "Number", "STRING_VALUE", "Logic", "AND", "OR", "Boolean", "TRUE",
	"FALSE", "Whitespace", "Fields_boolean", "Fields_string", "Fields_number",
	"OperatorContain", "OperatorEqual", "OperatorNumber", "Function", "Term",
	"In", "Notin", "InContain", "NotinContain", "InIp", "NotinIp", "Severity",
	"Status", "ValueIpString", "Ip_string", "Ip_byte", "Ip_value", "Array",
	"ArrayString", "ArrayIpString", "Literal", "NullValue",
}

var ruleNames = []string{
	"prog", "compareNumber", "compareString", "compareDate", "compareBoolean",
	"compareSeverity", "compareStatus", "compareCategory", "compareFeature",
	"expression",
}
var decisionToDFA = make([]*antlr.DFA, len(deserializedATN.DecisionToState))

func init() {
	for index, ds := range deserializedATN.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(ds, index)
	}
}

type GrammarParser struct {
	*antlr.BaseParser
}

func NewGrammarParser(input antlr.TokenStream) *GrammarParser {
	this := new(GrammarParser)

	this.BaseParser = antlr.NewBaseParser(input)

	this.Interpreter = antlr.NewParserATNSimulator(this, deserializedATN, decisionToDFA, antlr.NewPredictionContextCache())
	this.RuleNames = ruleNames
	this.LiteralNames = literalNames
	this.SymbolicNames = symbolicNames
	this.GrammarFileName = "Grammar.g4"

	return this
}

// GrammarParser tokens.
const (
	GrammarParserEOF             = antlr.TokenEOF
	GrammarParserT__0            = 1
	GrammarParserT__1            = 2
	GrammarParserT__2            = 3
	GrammarParserT__3            = 4
	GrammarParserT__4            = 5
	GrammarParserT__5            = 6
	GrammarParserT__6            = 7
	GrammarParserT__7            = 8
	GrammarParserT__8            = 9
	GrammarParserT__9            = 10
	GrammarParserT__10           = 11
	GrammarParserT__11           = 12
	GrammarParserT__12           = 13
	GrammarParserT__13           = 14
	GrammarParserT__14           = 15
	GrammarParserT__15           = 16
	GrammarParserT__16           = 17
	GrammarParserT__17           = 18
	GrammarParserT__18           = 19
	GrammarParserNumber          = 20
	GrammarParserSTRING_VALUE    = 21
	GrammarParserLogic           = 22
	GrammarParserAND             = 23
	GrammarParserOR              = 24
	GrammarParserBoolean         = 25
	GrammarParserTRUE            = 26
	GrammarParserFALSE           = 27
	GrammarParserWhitespace      = 28
	GrammarParserFields_boolean  = 29
	GrammarParserFields_string   = 30
	GrammarParserFields_number   = 31
	GrammarParserOperatorContain = 32
	GrammarParserOperatorEqual   = 33
	GrammarParserOperatorNumber  = 34
	GrammarParserFunction        = 35
	GrammarParserTerm            = 36
	GrammarParserIn              = 37
	GrammarParserNotin           = 38
	GrammarParserInContain       = 39
	GrammarParserNotinContain    = 40
	GrammarParserInIp            = 41
	GrammarParserNotinIp         = 42
	GrammarParserSeverity        = 43
	GrammarParserStatus          = 44
	GrammarParserValueIpString   = 45
	GrammarParserIp_string       = 46
	GrammarParserIp_byte         = 47
	GrammarParserIp_value        = 48
	GrammarParserArray           = 49
	GrammarParserArrayString     = 50
	GrammarParserArrayIpString   = 51
	GrammarParserLiteral         = 52
	GrammarParserNullValue       = 53
)

// GrammarParser rules.
const (
	GrammarParserRULE_prog            = 0
	GrammarParserRULE_compareNumber   = 1
	GrammarParserRULE_compareString   = 2
	GrammarParserRULE_compareDate     = 3
	GrammarParserRULE_compareBoolean  = 4
	GrammarParserRULE_compareSeverity = 5
	GrammarParserRULE_compareStatus   = 6
	GrammarParserRULE_compareCategory = 7
	GrammarParserRULE_compareFeature  = 8
	GrammarParserRULE_expression      = 9
)

// IProgContext is an interface to support dynamic dispatch.
type IProgContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsProgContext differentiates from other interfaces.
	IsProgContext()
}

type ProgContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyProgContext() *ProgContext {
	var p = new(ProgContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_prog
	return p
}

func (*ProgContext) IsProgContext() {}

func NewProgContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ProgContext {
	var p = new(ProgContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_prog

	return p
}

func (s *ProgContext) GetParser() antlr.Parser { return s.parser }

func (s *ProgContext) Expression() IExpressionContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IExpressionContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *ProgContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ProgContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ProgContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitProg(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) Prog() (localctx IProgContext) {
	localctx = NewProgContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, GrammarParserRULE_prog)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(20)
		p.expression(0)
	}

	return localctx
}

// ICompareNumberContext is an interface to support dynamic dispatch.
type ICompareNumberContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareNumberContext differentiates from other interfaces.
	IsCompareNumberContext()
}

type CompareNumberContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareNumberContext() *CompareNumberContext {
	var p = new(CompareNumberContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareNumber
	return p
}

func (*CompareNumberContext) IsCompareNumberContext() {}

func NewCompareNumberContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareNumberContext {
	var p = new(CompareNumberContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareNumber

	return p
}

func (s *CompareNumberContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareNumberContext) GetLeft() antlr.Token { return s.left }

func (s *CompareNumberContext) GetOp() antlr.Token { return s.op }

func (s *CompareNumberContext) GetRight() antlr.Token { return s.right }

func (s *CompareNumberContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareNumberContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareNumberContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareNumberContext) Fields_number() antlr.TerminalNode {
	return s.GetToken(GrammarParserFields_number, 0)
}

func (s *CompareNumberContext) Number() antlr.TerminalNode {
	return s.GetToken(GrammarParserNumber, 0)
}

func (s *CompareNumberContext) OperatorNumber() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorNumber, 0)
}

func (s *CompareNumberContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareNumberContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareNumberContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareNumberContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareNumber(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareNumber() (localctx ICompareNumberContext) {
	localctx = NewCompareNumberContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, GrammarParserRULE_compareNumber)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(22)

		var _m = p.Match(GrammarParserFields_number)

		localctx.(*CompareNumberContext).left = _m
	}
	{
		p.SetState(23)

		var _lt = p.GetTokenStream().LT(1)

		localctx.(*CompareNumberContext).op = _lt

		_la = p.GetTokenStream().LA(1)

		if !(_la == GrammarParserOperatorEqual || _la == GrammarParserOperatorNumber) {
			var _ri = p.GetErrorHandler().RecoverInline(p)

			localctx.(*CompareNumberContext).op = _ri
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	{
		p.SetState(24)

		var _m = p.Match(GrammarParserNumber)

		localctx.(*CompareNumberContext).right = _m
	}

	return localctx
}

// ICompareStringContext is an interface to support dynamic dispatch.
type ICompareStringContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareStringContext differentiates from other interfaces.
	IsCompareStringContext()
}

type CompareStringContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareStringContext() *CompareStringContext {
	var p = new(CompareStringContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareString
	return p
}

func (*CompareStringContext) IsCompareStringContext() {}

func NewCompareStringContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareStringContext {
	var p = new(CompareStringContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareString

	return p
}

func (s *CompareStringContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareStringContext) GetLeft() antlr.Token { return s.left }

func (s *CompareStringContext) GetOp() antlr.Token { return s.op }

func (s *CompareStringContext) GetRight() antlr.Token { return s.right }

func (s *CompareStringContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareStringContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareStringContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareStringContext) Fields_string() antlr.TerminalNode {
	return s.GetToken(GrammarParserFields_string, 0)
}

func (s *CompareStringContext) STRING_VALUE() antlr.TerminalNode {
	return s.GetToken(GrammarParserSTRING_VALUE, 0)
}

func (s *CompareStringContext) OperatorContain() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorContain, 0)
}

func (s *CompareStringContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareStringContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareStringContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareStringContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareString(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareString() (localctx ICompareStringContext) {
	localctx = NewCompareStringContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, GrammarParserRULE_compareString)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(26)

		var _m = p.Match(GrammarParserFields_string)

		localctx.(*CompareStringContext).left = _m
	}
	{
		p.SetState(27)

		var _lt = p.GetTokenStream().LT(1)

		localctx.(*CompareStringContext).op = _lt

		_la = p.GetTokenStream().LA(1)

		if !(_la == GrammarParserOperatorContain || _la == GrammarParserOperatorEqual) {
			var _ri = p.GetErrorHandler().RecoverInline(p)

			localctx.(*CompareStringContext).op = _ri
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	{
		p.SetState(28)

		var _m = p.Match(GrammarParserSTRING_VALUE)

		localctx.(*CompareStringContext).right = _m
	}

	return localctx
}

// ICompareDateContext is an interface to support dynamic dispatch.
type ICompareDateContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareDateContext differentiates from other interfaces.
	IsCompareDateContext()
}

type CompareDateContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareDateContext() *CompareDateContext {
	var p = new(CompareDateContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareDate
	return p
}

func (*CompareDateContext) IsCompareDateContext() {}

func NewCompareDateContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareDateContext {
	var p = new(CompareDateContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareDate

	return p
}

func (s *CompareDateContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareDateContext) GetLeft() antlr.Token { return s.left }

func (s *CompareDateContext) GetOp() antlr.Token { return s.op }

func (s *CompareDateContext) GetRight() antlr.Token { return s.right }

func (s *CompareDateContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareDateContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareDateContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareDateContext) STRING_VALUE() antlr.TerminalNode {
	return s.GetToken(GrammarParserSTRING_VALUE, 0)
}

func (s *CompareDateContext) OperatorNumber() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorNumber, 0)
}

func (s *CompareDateContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareDateContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareDateContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareDateContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareDate(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareDate() (localctx ICompareDateContext) {
	localctx = NewCompareDateContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, GrammarParserRULE_compareDate)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(30)

		var _m = p.Match(GrammarParserT__0)

		localctx.(*CompareDateContext).left = _m
	}
	{
		p.SetState(31)

		var _lt = p.GetTokenStream().LT(1)

		localctx.(*CompareDateContext).op = _lt

		_la = p.GetTokenStream().LA(1)

		if !(_la == GrammarParserOperatorEqual || _la == GrammarParserOperatorNumber) {
			var _ri = p.GetErrorHandler().RecoverInline(p)

			localctx.(*CompareDateContext).op = _ri
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	{
		p.SetState(32)

		var _m = p.Match(GrammarParserSTRING_VALUE)

		localctx.(*CompareDateContext).right = _m
	}

	return localctx
}

// ICompareBooleanContext is an interface to support dynamic dispatch.
type ICompareBooleanContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareBooleanContext differentiates from other interfaces.
	IsCompareBooleanContext()
}

type CompareBooleanContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareBooleanContext() *CompareBooleanContext {
	var p = new(CompareBooleanContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareBoolean
	return p
}

func (*CompareBooleanContext) IsCompareBooleanContext() {}

func NewCompareBooleanContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareBooleanContext {
	var p = new(CompareBooleanContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareBoolean

	return p
}

func (s *CompareBooleanContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareBooleanContext) GetLeft() antlr.Token { return s.left }

func (s *CompareBooleanContext) GetOp() antlr.Token { return s.op }

func (s *CompareBooleanContext) GetRight() antlr.Token { return s.right }

func (s *CompareBooleanContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareBooleanContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareBooleanContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareBooleanContext) Fields_boolean() antlr.TerminalNode {
	return s.GetToken(GrammarParserFields_boolean, 0)
}

func (s *CompareBooleanContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareBooleanContext) Boolean() antlr.TerminalNode {
	return s.GetToken(GrammarParserBoolean, 0)
}

func (s *CompareBooleanContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareBooleanContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareBooleanContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareBoolean(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareBoolean() (localctx ICompareBooleanContext) {
	localctx = NewCompareBooleanContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, GrammarParserRULE_compareBoolean)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(34)

		var _m = p.Match(GrammarParserFields_boolean)

		localctx.(*CompareBooleanContext).left = _m
	}
	{
		p.SetState(35)

		var _m = p.Match(GrammarParserOperatorEqual)

		localctx.(*CompareBooleanContext).op = _m
	}
	{
		p.SetState(36)

		var _m = p.Match(GrammarParserBoolean)

		localctx.(*CompareBooleanContext).right = _m
	}

	return localctx
}

// ICompareSeverityContext is an interface to support dynamic dispatch.
type ICompareSeverityContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareSeverityContext differentiates from other interfaces.
	IsCompareSeverityContext()
}

type CompareSeverityContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareSeverityContext() *CompareSeverityContext {
	var p = new(CompareSeverityContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareSeverity
	return p
}

func (*CompareSeverityContext) IsCompareSeverityContext() {}

func NewCompareSeverityContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareSeverityContext {
	var p = new(CompareSeverityContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareSeverity

	return p
}

func (s *CompareSeverityContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareSeverityContext) GetLeft() antlr.Token { return s.left }

func (s *CompareSeverityContext) GetOp() antlr.Token { return s.op }

func (s *CompareSeverityContext) GetRight() antlr.Token { return s.right }

func (s *CompareSeverityContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareSeverityContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareSeverityContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareSeverityContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareSeverityContext) Severity() antlr.TerminalNode {
	return s.GetToken(GrammarParserSeverity, 0)
}

func (s *CompareSeverityContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareSeverityContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareSeverityContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareSeverity(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareSeverity() (localctx ICompareSeverityContext) {
	localctx = NewCompareSeverityContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, GrammarParserRULE_compareSeverity)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(38)

		var _m = p.Match(GrammarParserT__1)

		localctx.(*CompareSeverityContext).left = _m
	}
	{
		p.SetState(39)

		var _m = p.Match(GrammarParserOperatorEqual)

		localctx.(*CompareSeverityContext).op = _m
	}
	{
		p.SetState(40)

		var _m = p.Match(GrammarParserSeverity)

		localctx.(*CompareSeverityContext).right = _m
	}

	return localctx
}

// ICompareStatusContext is an interface to support dynamic dispatch.
type ICompareStatusContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareStatusContext differentiates from other interfaces.
	IsCompareStatusContext()
}

type CompareStatusContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareStatusContext() *CompareStatusContext {
	var p = new(CompareStatusContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareStatus
	return p
}

func (*CompareStatusContext) IsCompareStatusContext() {}

func NewCompareStatusContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareStatusContext {
	var p = new(CompareStatusContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareStatus

	return p
}

func (s *CompareStatusContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareStatusContext) GetLeft() antlr.Token { return s.left }

func (s *CompareStatusContext) GetOp() antlr.Token { return s.op }

func (s *CompareStatusContext) GetRight() antlr.Token { return s.right }

func (s *CompareStatusContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareStatusContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareStatusContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareStatusContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareStatusContext) Status() antlr.TerminalNode {
	return s.GetToken(GrammarParserStatus, 0)
}

func (s *CompareStatusContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareStatusContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareStatusContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareStatus(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareStatus() (localctx ICompareStatusContext) {
	localctx = NewCompareStatusContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, GrammarParserRULE_compareStatus)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(42)

		var _m = p.Match(GrammarParserT__2)

		localctx.(*CompareStatusContext).left = _m
	}
	{
		p.SetState(43)

		var _m = p.Match(GrammarParserOperatorEqual)

		localctx.(*CompareStatusContext).op = _m
	}
	{
		p.SetState(44)

		var _m = p.Match(GrammarParserStatus)

		localctx.(*CompareStatusContext).right = _m
	}

	return localctx
}

// ICompareCategoryContext is an interface to support dynamic dispatch.
type ICompareCategoryContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareCategoryContext differentiates from other interfaces.
	IsCompareCategoryContext()
}

type CompareCategoryContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareCategoryContext() *CompareCategoryContext {
	var p = new(CompareCategoryContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareCategory
	return p
}

func (*CompareCategoryContext) IsCompareCategoryContext() {}

func NewCompareCategoryContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareCategoryContext {
	var p = new(CompareCategoryContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareCategory

	return p
}

func (s *CompareCategoryContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareCategoryContext) GetLeft() antlr.Token { return s.left }

func (s *CompareCategoryContext) GetOp() antlr.Token { return s.op }

func (s *CompareCategoryContext) GetRight() antlr.Token { return s.right }

func (s *CompareCategoryContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareCategoryContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareCategoryContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareCategoryContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareCategoryContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareCategoryContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareCategoryContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareCategory(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareCategory() (localctx ICompareCategoryContext) {
	localctx = NewCompareCategoryContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, GrammarParserRULE_compareCategory)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(46)

		var _m = p.Match(GrammarParserT__3)

		localctx.(*CompareCategoryContext).left = _m
	}
	{
		p.SetState(47)

		var _m = p.Match(GrammarParserOperatorEqual)

		localctx.(*CompareCategoryContext).op = _m
	}
	{
		p.SetState(48)

		var _lt = p.GetTokenStream().LT(1)

		localctx.(*CompareCategoryContext).right = _lt

		_la = p.GetTokenStream().LA(1)

		if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<GrammarParserT__4)|(1<<GrammarParserT__5)|(1<<GrammarParserT__6)|(1<<GrammarParserT__7)|(1<<GrammarParserT__8)|(1<<GrammarParserT__9)|(1<<GrammarParserT__10)|(1<<GrammarParserT__11)|(1<<GrammarParserT__12)|(1<<GrammarParserT__13))) != 0) {
			var _ri = p.GetErrorHandler().RecoverInline(p)

			localctx.(*CompareCategoryContext).right = _ri
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// ICompareFeatureContext is an interface to support dynamic dispatch.
type ICompareFeatureContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetLeft returns the left token.
	GetLeft() antlr.Token

	// GetOp returns the op token.
	GetOp() antlr.Token

	// GetRight returns the right token.
	GetRight() antlr.Token

	// SetLeft sets the left token.
	SetLeft(antlr.Token)

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// SetRight sets the right token.
	SetRight(antlr.Token)

	// IsCompareFeatureContext differentiates from other interfaces.
	IsCompareFeatureContext()
}

type CompareFeatureContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   antlr.Token
	op     antlr.Token
	right  antlr.Token
}

func NewEmptyCompareFeatureContext() *CompareFeatureContext {
	var p = new(CompareFeatureContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_compareFeature
	return p
}

func (*CompareFeatureContext) IsCompareFeatureContext() {}

func NewCompareFeatureContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompareFeatureContext {
	var p = new(CompareFeatureContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_compareFeature

	return p
}

func (s *CompareFeatureContext) GetParser() antlr.Parser { return s.parser }

func (s *CompareFeatureContext) GetLeft() antlr.Token { return s.left }

func (s *CompareFeatureContext) GetOp() antlr.Token { return s.op }

func (s *CompareFeatureContext) GetRight() antlr.Token { return s.right }

func (s *CompareFeatureContext) SetLeft(v antlr.Token) { s.left = v }

func (s *CompareFeatureContext) SetOp(v antlr.Token) { s.op = v }

func (s *CompareFeatureContext) SetRight(v antlr.Token) { s.right = v }

func (s *CompareFeatureContext) OperatorEqual() antlr.TerminalNode {
	return s.GetToken(GrammarParserOperatorEqual, 0)
}

func (s *CompareFeatureContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompareFeatureContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompareFeatureContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitCompareFeature(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) CompareFeature() (localctx ICompareFeatureContext) {
	localctx = NewCompareFeatureContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, GrammarParserRULE_compareFeature)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(50)

		var _m = p.Match(GrammarParserT__14)

		localctx.(*CompareFeatureContext).left = _m
	}
	{
		p.SetState(51)

		var _m = p.Match(GrammarParserOperatorEqual)

		localctx.(*CompareFeatureContext).op = _m
	}
	{
		p.SetState(52)

		var _lt = p.GetTokenStream().LT(1)

		localctx.(*CompareFeatureContext).right = _lt

		_la = p.GetTokenStream().LA(1)

		if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<GrammarParserT__4)|(1<<GrammarParserT__5)|(1<<GrammarParserT__9)|(1<<GrammarParserT__11)|(1<<GrammarParserT__15)|(1<<GrammarParserT__16))) != 0) {
			var _ri = p.GetErrorHandler().RecoverInline(p)

			localctx.(*CompareFeatureContext).right = _ri
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// IExpressionContext is an interface to support dynamic dispatch.
type IExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetOp returns the op token.
	GetOp() antlr.Token

	// SetOp sets the op token.
	SetOp(antlr.Token)

	// GetLeft returns the left rule contexts.
	GetLeft() IExpressionContext

	// GetInner returns the inner rule contexts.
	GetInner() IExpressionContext

	// GetRight returns the right rule contexts.
	GetRight() IExpressionContext

	// SetLeft sets the left rule contexts.
	SetLeft(IExpressionContext)

	// SetInner sets the inner rule contexts.
	SetInner(IExpressionContext)

	// SetRight sets the right rule contexts.
	SetRight(IExpressionContext)

	// IsExpressionContext differentiates from other interfaces.
	IsExpressionContext()
}

type ExpressionContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	left   IExpressionContext
	inner  IExpressionContext
	op     antlr.Token
	right  IExpressionContext
}

func NewEmptyExpressionContext() *ExpressionContext {
	var p = new(ExpressionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = GrammarParserRULE_expression
	return p
}

func (*ExpressionContext) IsExpressionContext() {}

func NewExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpressionContext {
	var p = new(ExpressionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = GrammarParserRULE_expression

	return p
}

func (s *ExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpressionContext) GetOp() antlr.Token { return s.op }

func (s *ExpressionContext) SetOp(v antlr.Token) { s.op = v }

func (s *ExpressionContext) GetLeft() IExpressionContext { return s.left }

func (s *ExpressionContext) GetInner() IExpressionContext { return s.inner }

func (s *ExpressionContext) GetRight() IExpressionContext { return s.right }

func (s *ExpressionContext) SetLeft(v IExpressionContext) { s.left = v }

func (s *ExpressionContext) SetInner(v IExpressionContext) { s.inner = v }

func (s *ExpressionContext) SetRight(v IExpressionContext) { s.right = v }

func (s *ExpressionContext) AllExpression() []IExpressionContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IExpressionContext)(nil)).Elem())
	var tst = make([]IExpressionContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IExpressionContext)
		}
	}

	return tst
}

func (s *ExpressionContext) Expression(i int) IExpressionContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IExpressionContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *ExpressionContext) CompareNumber() ICompareNumberContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareNumberContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareNumberContext)
}

func (s *ExpressionContext) CompareString() ICompareStringContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareStringContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareStringContext)
}

func (s *ExpressionContext) CompareSeverity() ICompareSeverityContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareSeverityContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareSeverityContext)
}

func (s *ExpressionContext) CompareDate() ICompareDateContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareDateContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareDateContext)
}

func (s *ExpressionContext) CompareStatus() ICompareStatusContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareStatusContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareStatusContext)
}

func (s *ExpressionContext) CompareBoolean() ICompareBooleanContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareBooleanContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareBooleanContext)
}

func (s *ExpressionContext) CompareCategory() ICompareCategoryContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareCategoryContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareCategoryContext)
}

func (s *ExpressionContext) CompareFeature() ICompareFeatureContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompareFeatureContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompareFeatureContext)
}

func (s *ExpressionContext) Logic() antlr.TerminalNode {
	return s.GetToken(GrammarParserLogic, 0)
}

func (s *ExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ExpressionContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case GrammarVisitor:
		return t.VisitExpression(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *GrammarParser) Expression() (localctx IExpressionContext) {
	return p.expression(0)
}

func (p *GrammarParser) expression(_p int) (localctx IExpressionContext) {
	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewExpressionContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx IExpressionContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 18
	p.EnterRecursionRule(localctx, 18, GrammarParserRULE_expression, _p)

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(67)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case GrammarParserT__17:
		{
			p.SetState(55)
			p.Match(GrammarParserT__17)
		}
		{
			p.SetState(56)

			var _x = p.expression(0)

			localctx.(*ExpressionContext).inner = _x
		}
		{
			p.SetState(57)
			p.Match(GrammarParserT__18)
		}

	case GrammarParserFields_number:
		{
			p.SetState(59)
			p.CompareNumber()
		}

	case GrammarParserFields_string:
		{
			p.SetState(60)
			p.CompareString()
		}

	case GrammarParserT__1:
		{
			p.SetState(61)
			p.CompareSeverity()
		}

	case GrammarParserT__0:
		{
			p.SetState(62)
			p.CompareDate()
		}

	case GrammarParserT__2:
		{
			p.SetState(63)
			p.CompareStatus()
		}

	case GrammarParserFields_boolean:
		{
			p.SetState(64)
			p.CompareBoolean()
		}

	case GrammarParserT__3:
		{
			p.SetState(65)
			p.CompareCategory()
		}

	case GrammarParserT__14:
		{
			p.SetState(66)
			p.CompareFeature()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}
	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(74)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 1, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			localctx = NewExpressionContext(p, _parentctx, _parentState)
			localctx.(*ExpressionContext).left = _prevctx
			p.PushNewRecursionContext(localctx, _startState, GrammarParserRULE_expression)
			p.SetState(69)

			if !(p.Precpred(p.GetParserRuleContext(), 10)) {
				panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 10)", ""))
			}
			{
				p.SetState(70)

				var _m = p.Match(GrammarParserLogic)

				localctx.(*ExpressionContext).op = _m
			}
			{
				p.SetState(71)

				var _x = p.expression(11)

				localctx.(*ExpressionContext).right = _x
			}

		}
		p.SetState(76)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 1, p.GetParserRuleContext())
	}

	return localctx
}

func (p *GrammarParser) Sempred(localctx antlr.RuleContext, ruleIndex, predIndex int) bool {
	switch ruleIndex {
	case 9:
		var t *ExpressionContext = nil
		if localctx != nil {
			t = localctx.(*ExpressionContext)
		}
		return p.Expression_Sempred(t, predIndex)

	default:
		panic("No predicate with index: " + fmt.Sprint(ruleIndex))
	}
}

func (p *GrammarParser) Expression_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	switch predIndex {
	case 0:
		return p.Precpred(p.GetParserRuleContext(), 10)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}
