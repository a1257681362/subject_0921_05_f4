package com.evops.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 日志敏感字段打码规则：手机号保留前 3 后 4；姓名按字数打码；通用规则保留头尾。
 */
class LogMaskerTest {

    @Test
    void phone_eleven_digits_keeps_3_and_4() {
        assertEquals("138****5678", LogMasker.maskPhone("13812345678"));
        assertEquals("138****5678", LogMasker.maskPhone(" 13812345678 "));
    }

    @Test
    void phone_other_length_falls_back_to_generic() {
        // 11 位座机走手机号规则；非 11 位走通用规则保留前 2 后 2
        assertEquals("010****5688", LogMasker.maskPhone("01012345688"));
        assertEquals("01******68", LogMasker.maskPhone("0101234568"));
        assertEquals("****", LogMasker.maskPhone("1234"));
    }

    @Test
    void phone_null_and_blank_pass_through() {
        assertNull(LogMasker.maskPhone(null));
        assertEquals("", LogMasker.maskPhone(""));
        assertEquals("  ", LogMasker.maskPhone("  "));
    }

    @Test
    void name_masked_by_length() {
        assertEquals("*", LogMasker.maskName("张"));
        assertEquals("张*", LogMasker.maskName("张三"));
        assertEquals("张*丰", LogMasker.maskName("张三丰"));
        assertEquals("欧**轩", LogMasker.maskName("欧阳明轩"));
    }

    @Test
    void generic_mask_keeps_head_and_tail() {
        assertEquals("ab****yz", LogMasker.mask("abcdefyz", 2, 2));
        assertEquals("***", LogMasker.mask("abc", 2, 2));
        assertNull(LogMasker.mask(null, 2, 2));
    }
}
