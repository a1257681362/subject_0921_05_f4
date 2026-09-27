package com.evops.common.trace;

import org.slf4j.MDC;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 链路追踪上下文（基于 SLF4J MDC）。
 * <p>
 * MDC 键：
 * <ul>
 *   <li>{@code traceId}：一次链路唯一标识。HTTP 入口由 {@link TraceIdFilter}
 *       从请求头 {@link #HEADER_TRACE_ID} 取用（未带则生成），响应头原样回带；
 *       异步线程由 {@link MdcTaskDecorator} 继承父线程快照；
 *       定时任务/启动恢复无上游请求，自行生成（前缀 {@code sched-}/{@code boot-}）。</li>
 *   <li>{@code orderNo}：当前处理的加工单号。业务处理一单前绑定、处理完解绑，
 *       一张加工单横跨"建档请求 + 后台核对 + 定时任务"的全部日志可用单号一键聚合。</li>
 *   <li>{@code jobNo}：当前批量任务号（后台执行/重跑期间绑定）。</li>
 * </ul>
 * 所有键值经 {@link #sanitize(String)} 清洗，杜绝换行/控制字符伪造日志行。
 */
public final class TraceContext {

    public static final String MDC_TRACE_ID = "traceId";
    public static final String MDC_ORDER_NO = "orderNo";
    public static final String MDC_JOB_NO = "jobNo";

    /** traceId 上游透传/响应回带的请求头名 */
    public static final String HEADER_TRACE_ID = "X-Trace-Id";

    private TraceContext() {
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final DateTimeFormatter TRACE_TIME = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    /**
     * 生成新 traceId：{@code <前缀>yyyyMMddHHmmss-<16位随机hex>}。
     * HTTP 入口用 {@code trace-}，定时任务用 {@code sched-}，启动恢复用 {@code boot-}，
     * 脱离请求线程的后台任务用 {@code job-}，一眼可辨来源。
     */
    public static String newTraceId(String prefix) {
        StringBuilder sb = new StringBuilder(prefix);
        sb.append(LocalDateTime.now().format(TRACE_TIME)).append('-');
        byte[] bytes = new byte[8];
        RANDOM.nextBytes(bytes);
        for (byte b : bytes) {
            sb.append(HEX[(b >> 4) & 0x0F]).append(HEX[b & 0x0F]);
        }
        return sb.toString();
    }

    /** 若无 traceId（脱离请求线程的执行入口）则补一个，返回当前生效的 traceId */
    public static String ensureTraceId(String prefix) {
        String existing = traceId();
        return existing != null ? existing : newTraceId(prefix);
    }

    /** 当前 traceId（未设置返回 null，日志 pattern 用 - 占位） */
    public static String traceId() {
        return MDC.get(MDC_TRACE_ID);
    }

    /** 设置/覆盖 traceId，返回可回滚的 AutoCloseable 绑定（try-with-resources 结束恢复原值） */
    public static TraceScope bindTraceId(String traceId) {
        return bind(MDC_TRACE_ID, traceId);
    }

    /** 绑定当前处理的加工单号 */
    public static TraceScope bindOrderNo(String orderNo) {
        return bind(MDC_ORDER_NO, orderNo);
    }

    /** 绑定当前批量任务号 */
    public static TraceScope bindJobNo(String jobNo) {
        return bind(MDC_JOB_NO, jobNo);
    }

    /** 还原父线程 MDC 快照（异步线程任务结束调用，避免线程复用时串号） */
    public static void restore(java.util.Map<String, String> snapshot) {
        MDC.clear();
        if (snapshot != null && !snapshot.isEmpty()) {
            MDC.setContextMap(snapshot);
        }
    }

    private static TraceScope bind(String key, String value) {
        String previous = MDC.get(key);
        String clean = sanitize(value);
        if (clean == null) {
            MDC.remove(key);
        } else {
            MDC.put(key, clean);
        }
        return () -> {
            if (previous == null) {
                MDC.remove(key);
            } else {
                MDC.put(key, previous);
            }
        };
    }

    /**
     * MDC 值清洗：null/空白视为未设置；剔除 CR/LF 与控制字符，防止日志注入；
     * 截断 128 字符，避免异常上游头把一行日志撑爆。
     */
    public static String sanitize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        StringBuilder sb = new StringBuilder(Math.min(trimmed.length(), 128));
        for (int i = 0; i < trimmed.length() && sb.length() < 128; i++) {
            char c = trimmed.charAt(i);
            if (c == '\r' || c == '\n' || Character.isISOControl(c)) {
                sb.append('_');
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** 单个 MDC 键的可回滚绑定 */
    @FunctionalInterface
    public interface TraceScope extends AutoCloseable {
        @Override
        void close();
    }
}
