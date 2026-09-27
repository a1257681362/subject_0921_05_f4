package com.evops.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * 统一异常出口。业务异常按业务码返回（可预期，不打日志）；
 * 约束冲突打 WARN、未预期异常打 ERROR——均经 MDC 自动带 traceId，报障按号聚合。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BizException.class)
    public ApiResponse<Void> handleBiz(BizException ex) {
        return ApiResponse.fail(ex.getBizCode(), ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ApiResponse<Void> handleValid(MethodArgumentNotValidException ex) {
        String detail = ex.getBindingResult().getFieldErrors().stream()
                .map(this::formatFieldError)
                .collect(Collectors.joining("；"));
        return ApiResponse.fail(BizCode.VALIDATION_FAILED,
                BizCode.VALIDATION_FAILED.getMessage() + "：" + detail);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ApiResponse<Void> handleUnreadable(HttpMessageNotReadableException ex) {
        return ApiResponse.fail(BizCode.VALIDATION_FAILED, "请求体格式不正确");
    }

    @ExceptionHandler(DuplicateKeyException.class)
    public ApiResponse<Void> handleDuplicateKey(DuplicateKeyException ex) {
        String msg = ex.getMessage() == null ? "" : ex.getMessage().toUpperCase();
        BizCode code = resolveDuplicateCode(msg);
        log.warn("数据唯一约束冲突 code={}", code.getCode());
        return ApiResponse.fail(code);
    }

    /** 只按约束/索引名判定：异常消息含整条 SQL，按表名列名匹配会误判（SQL 中所有列名同时出现） */
    private BizCode resolveDuplicateCode(String upperMsg) {
        if (upperMsg.contains("UK_ORDER_REQUEST")) { // 请求号唯一（重复提交），先于单号判定
            return BizCode.REQUEST_DUPLICATED;
        }
        if (upperMsg.contains("UK_BATCH_JOB_REQUEST")) {
            return BizCode.REQUEST_DUPLICATED;
        }
        if (upperMsg.contains("UK_ORDER_NO")) {
            return BizCode.ORDER_NO_DUPLICATED;
        }
        if (upperMsg.contains("UK_LENS_CODE")) {
            return BizCode.LENS_CODE_DUPLICATED;
        }
        if (upperMsg.contains("UK_ORDER_RX_ACTIVE")) {
            return BizCode.RX_EYE_DUPLICATED;
        }
        return BizCode.DATA_DUPLICATED;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ApiResponse<Void> handleIllegalArgument(IllegalArgumentException ex) {
        return ApiResponse.fail(BizCode.VALIDATION_FAILED, ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ApiResponse<Void> handleUnexpected(Exception ex) {
        // 未预期异常必须落日志（自动带 traceId）：响应只回通用文案，细节留在日志里按号查
        log.error("系统未预期异常", ex);
        return ApiResponse.fail(BizCode.SYSTEM_ERROR, "系统处理失败");
    }

    private String formatFieldError(FieldError error) {
        return error.getField() + " " + error.getDefaultMessage();
    }
}
