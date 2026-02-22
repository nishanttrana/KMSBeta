package pdfutil

import (
	"bytes"
	"fmt"
	"strings"
)

const (
	pageWidthPt     = 612
	pageHeightPt    = 792
	pageStartXPt    = 40
	pageStartYPt    = 760
	lineHeightPt    = 14
	linesPerPage    = 48
	maxCharsPerLine = 96
	maxTitleChars   = 96
	pdfFontName     = "Helvetica"
)

// RenderTextPDF renders a simple, valid multi-page PDF document containing text lines.
// The output is intentionally dependency-free and suitable for API report exports.
func RenderTextPDF(title string, lines []string) ([]byte, error) {
	title = strings.TrimSpace(sanitizeASCII(title))
	if title == "" {
		title = "Report"
	}
	title = truncateRunes(title, maxTitleChars)

	allLines := []string{title, ""}
	for _, line := range lines {
		for _, wrapped := range wrapLine(sanitizeASCII(line), maxCharsPerLine) {
			allLines = append(allLines, wrapped)
		}
	}
	if len(allLines) == 2 {
		allLines = append(allLines, "(no data)")
	}

	pages := chunkLines(allLines, linesPerPage)
	if len(pages) == 0 {
		pages = [][]string{{title, "", "(no data)"}}
	}

	totalPages := len(pages)
	fontID := 3 + totalPages*2
	totalObjects := fontID
	objects := make([]string, totalObjects+1)
	pageIDs := make([]int, 0, totalPages)

	for i, pageLines := range pages {
		pageID := 3 + i*2
		contentID := pageID + 1
		pageIDs = append(pageIDs, pageID)

		stream := renderPageStream(pageLines, i+1, totalPages)
		objects[contentID] = fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream)
		objects[pageID] = fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>",
			pageWidthPt, pageHeightPt, fontID, contentID,
		)
	}

	kids := make([]string, 0, len(pageIDs))
	for _, id := range pageIDs {
		kids = append(kids, fmt.Sprintf("%d 0 R", id))
	}

	objects[1] = "<< /Type /Catalog /Pages 2 0 R >>"
	objects[2] = fmt.Sprintf("<< /Type /Pages /Count %d /Kids [ %s ] >>", len(pageIDs), strings.Join(kids, " "))
	objects[fontID] = fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /%s >>", pdfFontName)

	buf := &bytes.Buffer{}
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	offsets := make([]int, totalObjects+1)
	for id := 1; id <= totalObjects; id++ {
		offsets[id] = buf.Len()
		if _, err := fmt.Fprintf(buf, "%d 0 obj\n%s\nendobj\n", id, objects[id]); err != nil {
			return nil, err
		}
	}

	xrefPos := buf.Len()
	if _, err := fmt.Fprintf(buf, "xref\n0 %d\n", totalObjects+1); err != nil {
		return nil, err
	}
	buf.WriteString("0000000000 65535 f \n")
	for id := 1; id <= totalObjects; id++ {
		if _, err := fmt.Fprintf(buf, "%010d 00000 n \n", offsets[id]); err != nil {
			return nil, err
		}
	}
	if _, err := fmt.Fprintf(
		buf,
		"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		totalObjects+1,
		xrefPos,
	); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func renderPageStream(lines []string, pageNum int, totalPages int) string {
	var b strings.Builder
	b.WriteString("BT\n")
	b.WriteString("/F1 11 Tf\n")
	b.WriteString(fmt.Sprintf("%d TL\n", lineHeightPt))
	b.WriteString(fmt.Sprintf("%d %d Td\n", pageStartXPt, pageStartYPt))

	header := fmt.Sprintf("Page %d/%d", pageNum, totalPages)
	b.WriteString("(" + escapePDFString(header) + ") Tj\n")

	for _, line := range lines {
		b.WriteString("T*\n")
		b.WriteString("(" + escapePDFString(line) + ") Tj\n")
	}

	b.WriteString("ET\n")
	return b.String()
}

func escapePDFString(in string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	return replacer.Replace(in)
}

func sanitizeASCII(in string) string {
	if in == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(in))
	for _, r := range in {
		switch {
		case r == '\t':
			b.WriteByte(' ')
		case r == '\n' || r == '\r':
			b.WriteByte(' ')
		case r >= 32 && r <= 126:
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return strings.TrimSpace(strings.Join(strings.Fields(b.String()), " "))
}

func wrapLine(line string, maxChars int) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return []string{""}
	}
	if len([]rune(line)) <= maxChars {
		return []string{line}
	}
	words := strings.Fields(line)
	if len(words) == 0 {
		return []string{line}
	}
	out := make([]string, 0, 2)
	cur := words[0]
	for _, w := range words[1:] {
		try := cur + " " + w
		if len([]rune(try)) <= maxChars {
			cur = try
			continue
		}
		out = append(out, cur)
		if len([]rune(w)) <= maxChars {
			cur = w
			continue
		}
		parts := splitRunes(w, maxChars)
		out = append(out, parts[:len(parts)-1]...)
		cur = parts[len(parts)-1]
	}
	out = append(out, cur)
	return out
}

func splitRunes(in string, size int) []string {
	rs := []rune(in)
	if len(rs) <= size {
		return []string{in}
	}
	out := make([]string, 0, (len(rs)/size)+1)
	for i := 0; i < len(rs); i += size {
		end := i + size
		if end > len(rs) {
			end = len(rs)
		}
		out = append(out, string(rs[i:end]))
	}
	return out
}

func truncateRunes(in string, max int) string {
	rs := []rune(in)
	if len(rs) <= max {
		return in
	}
	return string(rs[:max])
}

func chunkLines(lines []string, chunkSize int) [][]string {
	if chunkSize <= 0 {
		chunkSize = 1
	}
	out := make([][]string, 0, (len(lines)/chunkSize)+1)
	for i := 0; i < len(lines); i += chunkSize {
		end := i + chunkSize
		if end > len(lines) {
			end = len(lines)
		}
		out = append(out, lines[i:end])
	}
	return out
}
