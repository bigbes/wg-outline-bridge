package telegram

import (
	"fmt"
	"io"
	"mime/multipart"
)

// MultipartWriter wraps multipart.Writer with convenience methods for Telegram Bot API.
type MultipartWriter struct {
	w *multipart.Writer
}

// NewMultipartWriter creates a new MultipartWriter.
func NewMultipartWriter(w io.Writer) *MultipartWriter {
	return &MultipartWriter{w: multipart.NewWriter(w)}
}

// WriteField adds a text field.
func (m *MultipartWriter) WriteField(name, value string) {
	m.w.WriteField(name, value)
}

// WriteFile adds a file part with the given field name, filename, and content.
func (m *MultipartWriter) WriteFile(fieldName, filename string, data []byte) error {
	part, err := m.w.CreateFormFile(fieldName, filename)
	if err != nil {
		return fmt.Errorf("creating form file: %w", err)
	}
	_, err = part.Write(data)
	return err
}

// FormDataContentType returns the Content-Type header value.
func (m *MultipartWriter) FormDataContentType() string {
	return m.w.FormDataContentType()
}

// Close finalizes the multipart message.
func (m *MultipartWriter) Close() error {
	return m.w.Close()
}
