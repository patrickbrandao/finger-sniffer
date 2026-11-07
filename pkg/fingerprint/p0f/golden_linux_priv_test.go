//go:build linux_priv

package p0f

// Na vps602 (testes linux_priv do verify-full) o p0f.fp do deploy precisa existir: a comparação com o
// p0f -r não pode ser pulada.
func init() { requireRealDB = true }
