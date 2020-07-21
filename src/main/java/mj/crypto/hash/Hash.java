package mj.crypto.hash;

import mj.crypto.Result;

/**
 * @Project cryptography
 * @Author Montaser Sobaih
 * @Date 01-07-2020
 */

interface Hash<T> {

    Hash<T> clear();

    Hash<T> add(T input);

    default Result finalizeHash() {
        return finalizeHash(0);
    }

    Result finalizeHash(int times);
}