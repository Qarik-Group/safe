package vault_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/starkandwayne/safe/vault"
)

var _ = Describe("Utils", func() {
	Describe("ParsePath", func() {
		var inPath, inKey, inVersion string
		var outPath, outKey string
		var outVersion uint64

		var expPath, expKey string
		var expVersion uint64

		JustBeforeEach(func() {
			var fullInPath string = inPath
			if inKey != "" {
				fullInPath = fullInPath + ":" + inKey
			}
			if inVersion != "" {
				fullInPath = fullInPath + "^" + inVersion
			}
			outPath, outKey, outVersion = vault.ParsePath(fullInPath)
		})

		AfterEach(func() {
			inPath, inKey, inVersion = "", "", ""
			outPath, outKey = "", ""
			outVersion = 0
			expPath, expKey = "", ""
			expVersion = 0
		})

		assertPathValues := func() {
			It("should have the expected values", func() {
				By("having the correct path value")
				Expect(outPath).To(Equal(expPath))

				By("having the correct key value")
				Expect(outKey).To(Equal(expKey))

				By("having the correct version value")
				Expect(outVersion).To(Equal(expVersion))
			})
		}

		type ioStruct struct{ in, out, desc string }

		paths := []ioStruct{
			{"secret/foo", "secret/foo", "that is basic"},
			{`secret/f\:oo`, "secret/f:oo", "that has an escaped colon"},
			{`secret/f\^oo`, "secret/f^oo", "that has an escaped caret"},
		}

		keys := []ioStruct{
			{"bar", "bar", "that is basic"},
			{`b\:ar`, "b:ar", "that has an escaped colon"},
			{`b\^ar`, "b^ar", "that has an escaped caret"},
		}

		Context("with a path", func() {
			for i := range paths {
				path := paths[i]
				Context(path.desc, func() {
					BeforeEach(func() {
						inPath, expPath = path.in, path.out
					})

					assertPathValues()

					Context("with a key", func() {
						for j := range keys {
							key := keys[j]
							Context(key.desc, func() {
								BeforeEach(func() {
									inKey, expKey = key.in, key.out
								})

								assertPathValues()

								Context("with a version", func() {
									Context("that is zero", func() {
										BeforeEach(func() {
											inVersion, expVersion = "0", 0
										})

										assertPathValues()
									})

									Context("that is positive", func() {
										BeforeEach(func() {
											inVersion, expVersion = "21", 21
										})

										assertPathValues()
									})
								})
							})
						}
					})
				})
			}
		})

		Context("with a path that has an unescaped colon and a key", func() {
			BeforeEach(func() {
				inPath, inKey = "secret:foo", "bar"
				expPath, expKey = "secret:foo", "bar"
			})

			assertPathValues()
		})

		Context("with a path that has an unescaped caret and a version", func() {
			BeforeEach(func() {
				inPath, inVersion = "secret^foo", "2"
				expPath, expVersion = "secret^foo", 2
			})
		})
	})
})
