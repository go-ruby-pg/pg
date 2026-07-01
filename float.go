package pg

import "math"

func nan() float64    { return math.NaN() }
func posInf() float64 { return math.Inf(1) }
func negInf() float64 { return math.Inf(-1) }
