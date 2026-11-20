package ogcard

import (
	"errors"
	"fmt"
	"math"
	"strconv"
)

// A small SVG path-data parser, just enough for the Simple Icons marks of
// internal/webui/static/tagicons.svg: every command of the spec (M L H V C S
// Q T A Z, both cases), implicit repeats, compact numbers (".5.5", "1-2",
// "1e-3") and arc flags with no separator ("a1 1 0 00.5.5"). It turns all of
// it into absolute moves, lines, cubics and closes, which is all the
// rasteriser needs.

type pt struct{ x, y float64 }

// seg is one drawing step in absolute coordinates: 'M' (p[0]), 'L' (p[0]),
// 'C' (p[0], p[1] controls, p[2] end) or 'Z'.
type seg struct {
	op byte
	p  [3]pt
}

// pathScanner walks the path data byte by byte.
type pathScanner struct {
	d string
	i int
}

func isSep(c byte) bool {
	return c == ' ' || c == ',' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func (s *pathScanner) skip() {
	for s.i < len(s.d) && isSep(s.d[s.i]) {
		s.i++
	}
}

// numberNext: what follows starts a number (so the last command repeats).
func (s *pathScanner) numberNext() bool {
	s.skip()
	if s.i >= len(s.d) {
		return false
	}
	c := s.d[s.i]
	return c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9')
}

// num reads one number. A second '.' or a sign that isn't an exponent's
// ends it, which is how ".186.186" and "1-2" split.
func (s *pathScanner) num() (float64, error) {
	s.skip()
	start := s.i
	if s.i < len(s.d) && (s.d[s.i] == '-' || s.d[s.i] == '+') {
		s.i++
	}
	digits := 0
	for s.i < len(s.d) && s.d[s.i] >= '0' && s.d[s.i] <= '9' {
		s.i++
		digits++
	}
	if s.i < len(s.d) && s.d[s.i] == '.' {
		s.i++
		for s.i < len(s.d) && s.d[s.i] >= '0' && s.d[s.i] <= '9' {
			s.i++
			digits++
		}
	}
	if digits == 0 {
		return 0, fmt.Errorf("number expected at offset %d", start)
	}
	if s.i < len(s.d) && (s.d[s.i] == 'e' || s.d[s.i] == 'E') {
		j := s.i + 1
		if j < len(s.d) && (s.d[j] == '-' || s.d[j] == '+') {
			j++
		}
		k := j
		for k < len(s.d) && s.d[k] >= '0' && s.d[k] <= '9' {
			k++
		}
		if k == j {
			return 0, fmt.Errorf("bad exponent at offset %d", s.i)
		}
		s.i = k
	}
	v, err := strconv.ParseFloat(s.d[start:s.i], 64)
	if err != nil {
		return 0, fmt.Errorf("number %q: %w", s.d[start:s.i], err)
	}
	if math.IsInf(v, 0) || math.IsNaN(v) {
		return 0, fmt.Errorf("number %q out of range", s.d[start:s.i])
	}
	return v, nil
}

// flag reads an arc flag: a lone '0' or '1', which may be glued to
// whatever comes next.
func (s *pathScanner) flag() (bool, error) {
	s.skip()
	if s.i < len(s.d) {
		switch s.d[s.i] {
		case '0':
			s.i++
			return false, nil
		case '1':
			s.i++
			return true, nil
		}
	}
	return false, fmt.Errorf("arc flag expected at offset %d", s.i)
}

func (s *pathScanner) nums(n int) ([]float64, error) {
	v := make([]float64, n)
	for k := range v {
		var err error
		if v[k], err = s.num(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// parsePath turns path data into absolute segments. Anything it doesn't
// understand is an error; it never panics on odd input.
func parsePath(d string) ([]seg, error) {
	s := &pathScanner{d: d}
	var out []seg
	var cur, start pt
	var lastCtrl pt  // second control point of the last C/S, or the Q/T one
	var lastOp byte  // upper-case op of the previous command, for S and T
	var cmd byte     // the command in force (repeats on bare numbers)
	started := false // seen the first M
	for {
		s.skip()
		if s.i >= len(s.d) {
			break
		}
		c := s.d[s.i]
		switch {
		case isCmd(c):
			cmd = c
			s.i++
		case cmd != 0 && cmd != 'Z' && cmd != 'z' && s.numberNext():
			// implicit repeat: keep cmd (M/m already became L/l below)
		default:
			return nil, fmt.Errorf("unexpected %q at offset %d", c, s.i)
		}
		if !started && cmd != 'M' && cmd != 'm' {
			return nil, errors.New("path data must start with a moveto")
		}
		rel := cmd >= 'a'
		up := cmd &^ 0x20
		abs := func(x, y float64) pt {
			if rel {
				return pt{cur.x + x, cur.y + y}
			}
			return pt{x, y}
		}
		switch up {
		case 'Z':
			out = append(out, seg{op: 'Z'})
			cur = start
		case 'M':
			v, err := s.nums(2)
			if err != nil {
				return nil, err
			}
			cur = abs(v[0], v[1])
			start = cur
			started = true
			out = append(out, seg{op: 'M', p: [3]pt{cur}})
			// more pairs after a moveto are linetos
			if rel {
				cmd = 'l'
			} else {
				cmd = 'L'
			}
		case 'L':
			v, err := s.nums(2)
			if err != nil {
				return nil, err
			}
			cur = abs(v[0], v[1])
			out = append(out, seg{op: 'L', p: [3]pt{cur}})
		case 'H':
			v, err := s.num()
			if err != nil {
				return nil, err
			}
			if rel {
				v += cur.x
			}
			cur.x = v
			out = append(out, seg{op: 'L', p: [3]pt{cur}})
		case 'V':
			v, err := s.num()
			if err != nil {
				return nil, err
			}
			if rel {
				v += cur.y
			}
			cur.y = v
			out = append(out, seg{op: 'L', p: [3]pt{cur}})
		case 'C', 'S':
			n := 6
			if up == 'S' {
				n = 4
			}
			v, err := s.nums(n)
			if err != nil {
				return nil, err
			}
			var c1 pt
			if up == 'S' {
				c1 = cur
				if lastOp == 'C' || lastOp == 'S' {
					c1 = pt{2*cur.x - lastCtrl.x, 2*cur.y - lastCtrl.y}
				}
				v = append([]float64{0, 0}, v...)
			} else {
				c1 = abs(v[0], v[1])
			}
			c2, end := abs(v[2], v[3]), abs(v[4], v[5])
			out = append(out, seg{op: 'C', p: [3]pt{c1, c2, end}})
			lastCtrl, cur = c2, end
		case 'Q', 'T':
			var q, end pt
			if up == 'Q' {
				v, err := s.nums(4)
				if err != nil {
					return nil, err
				}
				q, end = abs(v[0], v[1]), abs(v[2], v[3])
			} else {
				v, err := s.nums(2)
				if err != nil {
					return nil, err
				}
				q = cur
				if lastOp == 'Q' || lastOp == 'T' {
					q = pt{2*cur.x - lastCtrl.x, 2*cur.y - lastCtrl.y}
				}
				end = abs(v[0], v[1])
			}
			out = append(out, quadSeg(cur, q, end))
			lastCtrl, cur = q, end
		case 'A':
			v, err := s.nums(3)
			if err != nil {
				return nil, err
			}
			large, err := s.flag()
			if err != nil {
				return nil, err
			}
			sweep, err := s.flag()
			if err != nil {
				return nil, err
			}
			e, err := s.nums(2)
			if err != nil {
				return nil, err
			}
			end := abs(e[0], e[1])
			out = append(out, arcSegs(cur, v[0], v[1], v[2], large, sweep, end)...)
			cur = end
		}
		lastOp = up
	}
	if !started {
		return nil, errors.New("empty path data")
	}
	return out, nil
}

func isCmd(c byte) bool {
	switch c &^ 0x20 {
	case 'M', 'L', 'H', 'V', 'C', 'S', 'Q', 'T', 'A', 'Z':
		return true
	}
	return false
}

// quadSeg writes a quadratic as the cubic that traces the same curve.
func quadSeg(p0, q, p1 pt) seg {
	return seg{op: 'C', p: [3]pt{
		{p0.x + 2.0/3*(q.x-p0.x), p0.y + 2.0/3*(q.y-p0.y)},
		{p1.x + 2.0/3*(q.x-p1.x), p1.y + 2.0/3*(q.y-p1.y)},
		p1,
	}}
}

// arcSegs converts an SVG elliptical arc (endpoint form) into cubics of at
// most 90 degrees each, following the SVG spec's implementation notes
// (F.6.5 and F.6.6: out-of-range radii are scaled up).
func arcSegs(p0 pt, rx, ry, phiDeg float64, large, sweep bool, p1 pt) []seg {
	if p0 == p1 {
		return nil
	}
	rx, ry = math.Abs(rx), math.Abs(ry)
	if rx == 0 || ry == 0 {
		return []seg{{op: 'L', p: [3]pt{p1}}}
	}
	phi := phiDeg * math.Pi / 180
	cos, sin := math.Cos(phi), math.Sin(phi)
	dx, dy := (p0.x-p1.x)/2, (p0.y-p1.y)/2
	x1 := cos*dx + sin*dy
	y1 := -sin*dx + cos*dy
	if l := x1*x1/(rx*rx) + y1*y1/(ry*ry); l > 1 {
		l = math.Sqrt(l)
		rx, ry = rx*l, ry*l
	}
	num := rx*rx*ry*ry - rx*rx*y1*y1 - ry*ry*x1*x1
	den := rx*rx*y1*y1 + ry*ry*x1*x1
	f := 0.0
	if num > 0 && den > 0 {
		f = math.Sqrt(num / den)
	}
	if large == sweep {
		f = -f
	}
	cx1, cy1 := f*rx*y1/ry, -f*ry*x1/rx
	cx := cos*cx1 - sin*cy1 + (p0.x+p1.x)/2
	cy := sin*cx1 + cos*cy1 + (p0.y+p1.y)/2
	angle := func(ux, uy, vx, vy float64) float64 {
		return math.Atan2(ux*vy-uy*vx, ux*vx+uy*vy)
	}
	ux, uy := (x1-cx1)/rx, (y1-cy1)/ry
	vx, vy := (-x1-cx1)/rx, (-y1-cy1)/ry
	t1 := angle(1, 0, ux, uy)
	dt := angle(ux, uy, vx, vy)
	if !sweep && dt > 0 {
		dt -= 2 * math.Pi
	} else if sweep && dt < 0 {
		dt += 2 * math.Pi
	}
	n := int(math.Ceil(math.Abs(dt) / (math.Pi / 2)))
	if n < 1 {
		n = 1
	}
	step := dt / float64(n)
	k := 4.0 / 3 * math.Tan(step/4)
	on := func(t float64) (pt, pt) { // point and derivative direction at t
		ct, st := math.Cos(t), math.Sin(t)
		p := pt{cx + rx*ct*cos - ry*st*sin, cy + rx*ct*sin + ry*st*cos}
		d := pt{-rx*st*cos - ry*ct*sin, -rx*st*sin + ry*ct*cos}
		return p, d
	}
	out := make([]seg, 0, n)
	a, da := on(t1)
	for i := 1; i <= n; i++ {
		b, db := on(t1 + float64(i)*step)
		if i == n {
			b = p1 // land exactly on the endpoint
		}
		out = append(out, seg{op: 'C', p: [3]pt{
			{a.x + k*da.x, a.y + k*da.y},
			{b.x - k*db.x, b.y - k*db.y},
			b,
		}})
		a, da = b, db
	}
	return out
}
