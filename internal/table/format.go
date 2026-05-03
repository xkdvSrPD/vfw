package table

import "fmt"

// FormatBytes formats a byte count in human-readable form (B, K, M, G, T).
func FormatBytes(n uint64) string {
	switch {
	case n >= 1099511627776:
		return fmt.Sprintf("%.1fT", float64(n)/1099511627776)
	case n >= 1073741824:
		return fmt.Sprintf("%.1fG", float64(n)/1073741824)
	case n >= 1048576:
		return fmt.Sprintf("%.0fM", float64(n)/1048576)
	case n >= 1024:
		return fmt.Sprintf("%.0fK", float64(n)/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// FormatCount formats a packet count in human-readable form.
func FormatCount(n uint64) string {
	switch {
	case n >= 1000000000:
		return fmt.Sprintf("%.1fG", float64(n)/1000000000)
	case n >= 1000000:
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	case n >= 1000:
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
