package jcs

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshal_SimpleMap(t *testing.T) {
	input := map[string]string{"b": "2", "a": "1"}
	data, err := Marshal(input)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Go's json.Marshal sorts map keys alphabetically
	require.JSONEq(t, `{"a":"1","b":"2"}`, string(data))
}

func TestMarshal_Struct(t *testing.T) {
	input := struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}{Name: "test", Age: 42}

	data, err := Marshal(input)
	require.NoError(t, err)
	require.Contains(t, string(data), `"name":"test"`)
	require.Contains(t, string(data), `"age":42`)
}

func TestMarshal_NaN(t *testing.T) {
	input := map[string]float64{"val": math.NaN()}
	_, err := Marshal(input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NaN or Infinity")
}

func TestMarshal_Inf(t *testing.T) {
	input := map[string]float64{"val": math.Inf(1)}
	_, err := Marshal(input)
	require.Error(t, err)
	require.Contains(t, err.Error(), "NaN or Infinity")
}

func TestMarshal_NegInf(t *testing.T) {
	input := map[string]float64{"val": math.Inf(-1)}
	_, err := Marshal(input)
	require.Error(t, err)
}

func TestMarshal_NestedNaN(t *testing.T) {
	input := map[string]interface{}{
		"outer": map[string]float64{"inner": math.NaN()},
	}
	_, err := Marshal(input)
	require.Error(t, err)
}

func TestMarshal_SliceWithNaN(t *testing.T) {
	input := []float64{1.0, math.NaN(), 3.0}
	_, err := Marshal(input)
	require.Error(t, err)
}

func TestMarshal_ValidFloat(t *testing.T) {
	input := map[string]float64{"val": 3.14}
	data, err := Marshal(input)
	require.NoError(t, err)
	require.Contains(t, string(data), "3.14")
}

func TestMarshal_Nil(t *testing.T) {
	data, err := Marshal(nil)
	require.NoError(t, err)
	require.Equal(t, "null", string(data))
}

func TestMarshal_Deterministic(t *testing.T) {
	input := map[string]int{"z": 3, "a": 1, "m": 2}
	data1, _ := Marshal(input)
	data2, _ := Marshal(input)
	require.Equal(t, string(data1), string(data2))
}
