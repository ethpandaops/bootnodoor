package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"math/big"
	"os"
	"strings"
	"time"
)

// GetTemplateFuncs will get the template functions
func GetTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"includeHTML": IncludeHTML,
		"html":        func(x string) template.HTML { return template.HTML(x) },
		"bigIntCmp":   func(i *big.Int, j int) int { return i.Cmp(big.NewInt(int64(j))) },
		"mod":         func(i, j int) bool { return i%j == 0 },
		"sub":         func(i, j int) int { return i - j },
		"subUI64":     func(i, j uint64) uint64 { return i - j },
		"add":         func(i, j int) int { return i + j },
		"addI64":      func(i, j int64) int64 { return i + j },
		"addUI64":     func(i, j uint64) uint64 { return i + j },
		"addFloat64":  func(i, j float64) float64 { return i + j },
		"mul":         func(i, j float64) float64 { return i * j },
		"div":         func(i, j float64) float64 { return i / j },
		"divInt":      func(i, j int) float64 { return float64(i) / float64(j) },
		"nef":         func(i, j float64) bool { return i != j },
		"gtf":         func(i, j float64) bool { return i > j },
		"ltf":         func(i, j float64) bool { return i < j },
		"inlist":      checkInList,
		"round": func(i float64, n int) float64 {
			return math.Round(i*math.Pow10(n)) / math.Pow10(n)
		},
		"percent":        func(i float64) float64 { return i * 100 },
		"contains":       strings.Contains,
		"formatTimeDiff": FormatTimeDiff,
		"now":            func() int64 { return time.Now().Unix() },
		"toInt64":        func(f float64) int64 { return int64(f) },
		"toFloat64":      func(i int) float64 { return float64(i) },
		"divDuration":    func(d time.Duration, divisor int64) float64 { return float64(d) / float64(divisor) },
		"jsonMarshal":    JSONMarshal,
	}
}

func checkInList(item, list string) bool {
	items := strings.Split(list, ",")
	for _, i := range items {
		if i == item {
			return true
		}
	}
	return false
}

func IncludeHTML(path string) template.HTML {
	b, err := os.ReadFile(path)
	if err != nil {
		logger.Printf("includeHTML - error reading file: %v", err)
		return ""
	}
	return template.HTML(string(b))
}

func FormatTimeDiff(ts time.Time) template.HTML {
	// Handle zero time (never set)
	if ts.IsZero() {
		return template.HTML("<span class=\"text-muted\">never</span>")
	}

	// Calculate duration since the timestamp (for past times)
	duration := time.Since(ts)
	var timeStr string
	absDuration := duration.Abs()

	if absDuration < 1*time.Second {
		return template.HTML("now")
	} else if absDuration < 60*time.Second {
		timeStr = fmt.Sprintf("%v sec", uint(absDuration.Seconds()))
	} else if absDuration < 60*time.Minute {
		timeStr = fmt.Sprintf("%v min", uint(absDuration.Minutes()))
	} else if absDuration < 24*time.Hour {
		timeStr = fmt.Sprintf("%v hr", uint(absDuration.Hours()))
	} else {
		timeStr = fmt.Sprintf("%v days", uint(absDuration.Hours()/24))
	}

	if duration < 0 {
		// Future time
		return template.HTML(fmt.Sprintf("in %v", timeStr))
	} else {
		// Past time
		return template.HTML(fmt.Sprintf("%v ago", timeStr))
	}
}

// JSONMarshal converts a Go value to JSON for use in templates
func JSONMarshal(v interface{}) template.JS {
	b, err := json.Marshal(v)
	if err != nil {
		logger.Printf("jsonMarshal - error marshaling: %v", err)
		return template.JS("{}")
	}
	return template.JS(b)
}
