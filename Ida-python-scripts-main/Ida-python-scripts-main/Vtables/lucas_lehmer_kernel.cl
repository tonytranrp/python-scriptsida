__kernel void lucas_lehmer(__global int* result, int p) {
    int m = (1 << p) - 1;
    int s = 4;
    for (int i = 0; i < p - 2; ++i) {
        s = (s * s - 2) % m;
    }
    result[0] = (s == 0 && m);
}
#C:/Users/tonyt/Videos/python-scriptsida/Ida-python-scripts-main/Ida-python-scripts-main/Vtables/