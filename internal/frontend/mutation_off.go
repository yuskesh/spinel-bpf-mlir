package frontend

// mutation is the hook for the mutation controls of differential testing. It is always false in a production build (it works
// only in test builds that enable the mutation hooks).
func mutation(string) bool { return false }
