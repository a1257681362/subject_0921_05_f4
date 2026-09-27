package com.evops.common.trace;

import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;

import java.util.Map;

/**
 * 异步任务 MDC 传递装饰器：提交任务时快照调用方线程的 MDC，
 * 工作线程执行前还原快照，执行结束恢复工作线程原有上下文。
 * <p>
 * 关键两点：
 * <ul>
 *   <li>快照在 {@link #decorate(Runnable)}（提交线程）时抓取，而非任务运行时——
 *       运行时已在池线程，抓不到请求线程的 traceId；</li>
 *   <li>finally 必须还原工作线程旧值，线程池线程复用否则会把上一任务的 traceId 带给下一任务。</li>
 * </ul>
 * 任务体内如需按加工单切换 orderNo，用 {@link TraceContext#bindOrderNo} 即可，
 * 关闭绑定时自动回到本快照。
 */
public class MdcTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        // 提交方（通常是 HTTP 请求线程）的 MDC 快照
        Map<String, String> callerSnapshot = MDC.getCopyOfContextMap();
        return () -> {
            Map<String, String> workerPrevious = MDC.getCopyOfContextMap();
            TraceContext.restore(callerSnapshot);
            try {
                runnable.run();
            } finally {
                TraceContext.restore(workerPrevious);
            }
        };
    }
}
