package mj.crypto.hash;

import mj.crypto.Result;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 01-07-2020
 */

interface Mac<T> {

    Mac<T> clear();

    Mac<T> add(T input);

    default Result finalizeMac() {
        return finalizeMac(1);
    }

    Result finalizeMac(int times);
}