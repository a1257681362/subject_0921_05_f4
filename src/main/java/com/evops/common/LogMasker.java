package com.evops.common;

/**
 * 敏感字段入日志前的打码工具（总部质控要求：敏感字段入日志前必须打码）。
 * <p>
 * 与 sensitive 包的"敏感词打码"不同：那里是业务文本守门，这里是日志 PII 脱敏。
 * 约定：任何日志输出客户手机号、姓名前必须过本工具；订单号、任务号、门店编码不算敏感。
 */
public final class LogMasker {

    private LogMasker() {
    }

    /**
     * 手机号：11 位保留前 3 后 4（138****5678）；其他长度按通用规则保留前 2 后 2。
     * null/空白原样返回（日志里本就打不出内容）。
     */
    public static String maskPhone(String phone) {
        if (phone == null || phone.trim().isEmpty()) {
            return phone;
        }
        String trimmed = phone.trim();
        if (trimmed.length() == 11) {
            return trimmed.substring(0, 3) + "****" + trimmed.substring(7);
        }
        return mask(trimmed, 2, 2);
    }

    /**
     * 姓名：2 字 → 张*；3 字 → 张*明；4 字及以上 → 张**明。
     * 仅用于日志展示，不落库、不影响业务数据。
     */
    public static String maskName(String name) {
        if (name == null || name.trim().isEmpty()) {
            return name;
        }
        String trimmed = name.trim();
        if (trimmed.length() == 1) {
            return "*";
        }
        if (trimmed.length() == 2) {
            return trimmed.charAt(0) + "*";
        }
        if (trimmed.length() == 3) {
            return trimmed.charAt(0) + "*" + trimmed.charAt(2);
        }
        return trimmed.charAt(0) + "**" + trimmed.charAt(trimmed.length() - 1);
    }

    /** 通用打码：保留前 keepHead 后 keepTail，中间以 * 填充（长度不足时全 *） */
    public static String mask(String text, int keepHead, int keepTail) {
        if (text == null) {
            return null;
        }
        if (text.length() <= keepHead + keepTail) {
            StringBuilder sb = new StringBuilder(text.length());
            for (int i = 0; i < text.length(); i++) {
                sb.append('*');
            }
            return sb.toString();
        }
        StringBuilder sb = new StringBuilder(text.length());
        sb.append(text, 0, keepHead);
        for (int i = keepHead; i < text.length() - keepTail; i++) {
            sb.append('*');
        }
        sb.append(text.substring(text.length() - keepTail));
        return sb.toString();
    }
}
