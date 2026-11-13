package privacyengine

import (
	"context"
	"net/http"

	"github.com/yetone/magpie/internal/gwmw"
)

// Session binds request protection and reply restoration to the engine that
// handled the request. Its implementation and capability checks stay here.
type Session struct {
	ctx    context.Context
	masker gwmw.Masker
	info   Info
}

func (s *Session) Engine() Info { return s.info }

type Protected[T any] struct {
	Body  T
	Hits  []gwmw.Hit
	Count int
}

func (s *Session) ProtectJSON(body []byte) (Protected[[]byte], error) {
	return gwmw.Safely(func() Protected[[]byte] {
		switch m := s.masker.(type) {
		case gwmw.ContextTeller:
			out, hits := m.JSONHitsContext(s.ctx, body)
			return Protected[[]byte]{Body: out, Hits: hits}
		case gwmw.Teller:
			out, hits := m.JSONHits(body)
			return Protected[[]byte]{Body: out, Hits: hits}
		default:
			out, n := m.JSON(body)
			return Protected[[]byte]{Body: out, Count: n}
		}
	})
}

// ProtectTexts batches fields when supported and stops at the first block.
func (s *Session) ProtectTexts(texts []string) (Protected[[]string], error) {
	return gwmw.Safely(func() Protected[[]string] {
		if batch, ok := s.masker.(interface {
			TextsHitsContext(context.Context, []string) ([]string, []gwmw.Hit)
		}); ok {
			out, hits := batch.TextsHitsContext(s.ctx, texts)
			return Protected[[]string]{Body: out, Hits: hits}
		}
		result := Protected[[]string]{Body: texts}
		for i, text := range texts {
			if text == "" {
				continue
			}
			var hits []gwmw.Hit
			var count int
			switch m := s.masker.(type) {
			case gwmw.ContextTeller:
				text, hits = m.TextHitsContext(s.ctx, text)
			case gwmw.Teller:
				text, hits = m.TextHits(text)
			default:
				text, count = m.Text(text)
			}
			result.Body[i] = text
			result.Hits = append(result.Hits, hits...)
			result.Count += count
			if gwmw.Blocks(hits) {
				break
			}
		}
		return result
	})
}

func (s *Session) RestoreText(text string) string {
	if s == nil {
		return text
	}
	return s.masker.Restore(text, false)
}

func (s *Session) WrapReply(w http.ResponseWriter, notice bool) (http.ResponseWriter, func(), func() map[string]int) {
	writer := s.masker.Writer
	if presenter, ok := s.masker.(interface {
		WriterWithNotice(http.ResponseWriter) (http.ResponseWriter, func())
	}); ok && notice {
		writer = presenter.WriterWithNotice
	}
	w, done := writer(w)
	var put func() map[string]int
	if counted, ok := w.(interface{ Put() map[string]int }); ok {
		put = counted.Put
	}
	return w, done, put
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	if closer, ok := s.masker.(interface{ Close() }); ok {
		closer.Close()
	}
}
