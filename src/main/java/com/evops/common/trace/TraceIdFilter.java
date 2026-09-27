package com.evops.common.trace;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 全链路 traceId 的 HTTP 入口（最高优先级，先于 Shiro/业务执行）：
 * <ol>
 *   <li>优先沿用上游请求头 {@link TraceContext#HEADER_TRACE_ID}（网关联调可透传），
 *       未带则由 {@link TraceContext#newTraceId(String)} 生成 {@code trace-...}；</li>
 *   <li>写入 MDC，本请求内所有日志（含异常处理器日志）自动带上；</li>
 *   <li>响应头 {@code X-Trace-Id} 原样回带，前端/报障凭此号一键聚合日志；</li>
 *   <li>请求结束清理 MDC，Tomcat 线程复用不串号。</li>
 * </ol>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TraceIdFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String traceId = TraceContext.sanitize(request.getHeader(TraceContext.HEADER_TRACE_ID));
        if (traceId == null) {
            traceId = TraceContext.newTraceId("trace-");
        }
        MDC.put(TraceContext.MDC_TRACE_ID, traceId);
        // 先回带响应头：业务中途异常也保证拿得到 traceId
        response.setHeader(TraceContext.HEADER_TRACE_ID, traceId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(TraceContext.MDC_TRACE_ID);
            MDC.remove(TraceContext.MDC_ORDER_NO);
            MDC.remove(TraceContext.MDC_JOB_NO);
        }
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }
}
