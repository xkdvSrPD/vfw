// Package table renders simple terminal tables for vfw commands.
package table

import (
	"fmt"
	"strings"

	"vfw/internal/model"
)

// RenderRules renders the current rule set as a plain text table.
func RenderRules(rules []model.Rule) string {
	if len(rules) == 0 {
		return "No rules configured.\n"
	}
	headers := []string{"#", "PORT", "PROTO", "FROM", "IPSET", "COMMAND"}
	rows := make([][]string, 0, len(rules))
	for index, rule := range rules {
		rows = append(rows, []string{
			fmt.Sprintf("%d", index+1),
			fmt.Sprintf("%d", rule.Port),
			rule.ProtocolLabel(),
			rule.SourceLabel(),
			rule.SetName,
			rule.CanonicalCommand(),
		})
	}

	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var builder strings.Builder
	builder.WriteString(renderRow(headers, widths))
	builder.WriteString(renderSeparator(widths))
	for _, row := range rows {
		builder.WriteString(renderRow(row, widths))
	}
	return builder.String()
}

func renderRow(row []string, widths []int) string {
	parts := make([]string, 0, len(row))
	for index, cell := range row {
		parts = append(parts, padRight(cell, widths[index]))
	}
	return strings.Join(parts, "  ") + "\n"
}

func renderSeparator(widths []int) string {
	parts := make([]string, 0, len(widths))
	for _, width := range widths {
		parts = append(parts, strings.Repeat("-", width))
	}
	return strings.Join(parts, "  ") + "\n"
}

func padRight(value string, width int) string {
	if len(value) >= width {
		return value
	}
	return value + strings.Repeat(" ", width-len(value))
}
