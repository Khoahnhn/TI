package search

import (
	"encoding/json"
	"os"

	"github.com/antlr/antlr4/runtime/Go/antlr"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/utils/search/parser"
)

type ParserService struct {
	logger  pencil.Logger
	visitor *grammarVisitor
	parser  *parser.GrammarParser
	lexer   *parser.GrammarLexer
	tokens  *antlr.CommonTokenStream
	errMsg  *string
	engine  string
}

// NewSearchService create a search query parser based on search engine
func NewSearchService(engine string) *ParserService {
	logger, _ := pencil.New(Module, pencil.DebugLevel, true, os.Stdout)
	return &ParserService{
		logger: logger,
		engine: engine,
	}
}

func (inst *ParserService) initQuery(q string) {
	input := antlr.NewInputStream(q)
	lexer := parser.NewGrammarLexer(input)
	lexer.RemoveErrorListeners()
	inst.parser.SetInputStream(antlr.NewCommonTokenStream(lexer, 0))
}

func (inst *ParserService) Query(q string) interface{} {
	visitor := new(grammarVisitor)
	if inst.engine == "es" {
		visitor.Query = new(grammarES)
	} else if inst.engine == "mongo" {
		visitor.Query = new(grammarES)
	}

	errMsg := ""
	lexer := parser.NewGrammarLexer(antlr.NewInputStream(q))
	lexer.RemoveErrorListeners()
	p := parser.NewGrammarParser(antlr.NewCommonTokenStream(lexer, 0))
	p.RemoveErrorListeners()
	p.AddErrorListener(&errorListener{
		Err: &errMsg,
	})
	p.BuildParseTrees = true
	tree := p.Prog()
	if len(errMsg) > 0 {
		errMsg = ""
		return nil
	}
	res := visitor.Visit(tree)
	data, err := json.Marshal(res)
	if err != nil {
		inst.logger.Errorf("failed!, reason: %v", err)
		return res
	}
	// Success
	inst.logger.Infof("query: %s", string(data))
	return res
}
