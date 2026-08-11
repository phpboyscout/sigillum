package opfile

// NewWriterForTest builds a Writer over a supplied temporary file, so a test
// can observe the ordering Commit relies on.
func NewWriterForTest(tmp tempFile, final string) *Writer {
	return &Writer{tmp: tmp, final: final}
}
