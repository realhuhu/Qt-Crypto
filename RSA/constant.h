namespace RSA_CONSTANT {
    static const qulonglong p = 65537;
    static const qulonglong q = 65539;
    static const qulonglong m = (p - 1) * (q - 1);
    static const qulonglong n = p * q;
}