//go:build itest

package itest

var testCases = []*testCase{
	{
		name: "loop pkscript",
		test: testLoopPkScript,
	},
}

var optionalTestCases = []*testCase{}
