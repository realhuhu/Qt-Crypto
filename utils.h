struct {
    qulonglong x, y;
} g; // 全局变量

//扩展欧几里得算法求最大公约数，计算ax+by=gcd(a,b)的x、y和gcd(a,b)
qulonglong extGCD(qulonglong a, qulonglong b) {
    if (b == 0) {
        g.x = 1;
        g.y = 0;
        return a;
    }
    qulonglong ret = extGCD(b, a % b);
    qulonglong t = g.x;
    g.x = g.y;
    g.y = t - a / b * g.y;
    return ret;
}

//求a^-1 (mod m)，若不存在逆元则返回1
qulonglong modReverse(qulonglong a, qulonglong m) {
    qulonglong gcd = extGCD(a, m);
    if (gcd != 1) {
        return 0;
    } else {
        return (g.x + m) % m;
    }
}

// 求x^y % mod 的值
qulonglong modPow(qulonglong x, qulonglong y, const qulonglong mod) {
    qulonglong res = 1;
    while (y) {
        if (y % 2) res = (res * x) % mod;
        x = (x * x) % mod;
        y /= 2;
    }
    return res;
}
