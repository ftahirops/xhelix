package brpparser

import (
	"fmt"
	"strings"
)

// nginxToken is one token from an nginx config file.
type nginxToken struct {
	kind nginxTokKind
	text string
}

type nginxTokKind uint8

const (
	nginxTokDirective  nginxTokKind = iota + 1 // first identifier on a line/after ;
	nginxTokArg                                // subsequent identifiers / quoted strings
	nginxTokSemi                               // ;
	nginxTokOpenBrace                          // {
	nginxTokCloseBrace                         // }
)

func (t nginxToken) String() string {
	switch t.kind {
	case nginxTokSemi:
		return ";"
	case nginxTokOpenBrace:
		return "{"
	case nginxTokCloseBrace:
		return "}"
	}
	return fmt.Sprintf("%q", t.text)
}

// tokenizeNginx splits an nginx config into a flat token stream. Handles:
//   - # comments to end of line
//   - "double-quoted" and 'single-quoted' strings (with \\ \" escapes)
//   - whitespace separation
//   - ; { } as standalone tokens
//
// The parser layer assigns Directive vs Arg semantics based on position.
func tokenizeNginx(src string) ([]nginxToken, error) {
	var out []nginxToken
	i := 0
	atStart := true // we're at the start of a statement → next ident is Directive

	for i < len(src) {
		c := src[i]
		// Whitespace.
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		// Comment to end of line.
		if c == '#' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			continue
		}
		// Punctuation.
		if c == ';' {
			out = append(out, nginxToken{kind: nginxTokSemi})
			i++
			atStart = true
			continue
		}
		if c == '{' {
			out = append(out, nginxToken{kind: nginxTokOpenBrace})
			i++
			atStart = true
			continue
		}
		if c == '}' {
			out = append(out, nginxToken{kind: nginxTokCloseBrace})
			i++
			atStart = true
			continue
		}
		// Quoted strings.
		if c == '"' || c == '\'' {
			quote := c
			i++
			var sb strings.Builder
			for i < len(src) && src[i] != quote {
				if src[i] == '\\' && i+1 < len(src) {
					sb.WriteByte(src[i+1])
					i += 2
					continue
				}
				sb.WriteByte(src[i])
				i++
			}
			if i >= len(src) {
				return nil, fmt.Errorf("unterminated quoted string")
			}
			i++ // closing quote
			tk := nginxTokArg
			if atStart {
				tk = nginxTokDirective
			}
			out = append(out, nginxToken{kind: tk, text: sb.String()})
			atStart = false
			continue
		}
		// Bare identifier — read until whitespace or punctuation.
		start := i
		for i < len(src) {
			c := src[i]
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
				c == ';' || c == '{' || c == '}' || c == '#' {
				break
			}
			i++
		}
		if i > start {
			tk := nginxTokArg
			if atStart {
				tk = nginxTokDirective
			}
			out = append(out, nginxToken{kind: tk, text: src[start:i]})
			atStart = false
		}
	}
	return out, nil
}
