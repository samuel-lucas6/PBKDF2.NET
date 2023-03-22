using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;
using Pbkdf2DotNet;

namespace Pbkdf2DotNetTests;

[TestClass]
public class PBKDF2Tests
{
    // https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.7.0:pbkdf2/pbkdf2_test.go
    public static IEnumerable<object[]> GoTestVectors()
    {
        yield return new object[]
        {
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            "password",
            "salt",
            1
        };
        yield return new object[]
        {
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            "password",
            "salt",
            2
        };
        yield return new object[]
        {
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            "password",
            "salt",
            4096
        };
        yield return new object[]
        {
            "cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46",
            "password",
            "salt",
            16777216
        };
        yield return new object[]
        {
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096
        };
        yield return new object[]
        {
            "89b69d0516f829893c696226650a8687",
            "pass\0word",
            "sa\0lt",
            4096
        };
    }
    
    // https://www.rfc-editor.org/rfc/rfc7914#section-11
    public static IEnumerable<object[]> ScryptTestVectors()
    {
        yield return new object[]
        {
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            "passwd",
            "salt",
            1
        };
        yield return new object[]
        {
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
            "Password",
            "NaCl",
            80000
        };
    }
    
    public static IEnumerable<object[]> InvalidParameters()
    {
        yield return new object[] { PBKDF2.KeySize, PBKDF2.KeySize, PBKDF2.SaltSize, -1, HashAlgorithmName.SHA256.Name };
        yield return new object[] { PBKDF2.KeySize, PBKDF2.KeySize, PBKDF2.SaltSize, 0, HashAlgorithmName.SHA256.Name };
        yield return new object[] { PBKDF2.KeySize, PBKDF2.KeySize, PBKDF2.SaltSize, 1, HashAlgorithmName.MD5.Name };
        yield return new object[] { PBKDF2.KeySize, PBKDF2.KeySize, PBKDF2.SaltSize, 1, HashAlgorithmName.SHA1.Name };
    }
    
    [TestMethod]
    [DynamicData(nameof(GoTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(ScryptTestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string outputKeyingMaterial, string password, string salt, int iterations)
    {
        Span<byte> o = stackalloc byte[outputKeyingMaterial.Length / 2];
        Span<byte> p = Encoding.UTF8.GetBytes(password);
        Span<byte> s = Encoding.UTF8.GetBytes(salt);
        
        PBKDF2.DeriveKey(o, p, s, iterations, HashAlgorithmName.SHA256);
        
        Assert.AreEqual(outputKeyingMaterial, Convert.ToHexString(o).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameters), DynamicDataSourceType.Method)]
    public void DeriveKey_Invalid(int outputKeyingMaterialSize, int passwordSize, int saltSize, int iterations, string hashAlgorithm)
    {
        var o = new byte[outputKeyingMaterialSize];
        var p = new byte[passwordSize];
        var s = new byte[saltSize];
        var h = new HashAlgorithmName(hashAlgorithm);
        
        if (h == HashAlgorithmName.MD5 || h == HashAlgorithmName.SHA1) {
            Assert.ThrowsException<NotSupportedException>(() => PBKDF2.DeriveKey(o, p, s, iterations, h));
        }
        else {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => PBKDF2.DeriveKey(o, p, s, iterations, h));
        }
    }
}