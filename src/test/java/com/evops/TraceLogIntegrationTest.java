package com.evops;

import com.evops.batch.maintenance.BatchJobMaintenance;
import com.evops.sensitive.SensitiveWordManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.shiro.spring.web.config.DefaultShiroFilterChainDefinition;
import org.apache.shiro.spring.web.config.ShiroFilterChainDefinition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 链路日志端到端测试（总部质控要求验收），样例数据挑最绕的一条路：
 * <pre>
 * 拦截级敏感词整单拒绝（留痕独立事务）→ 打码级敏感词（全角＋插空绕法）建档放行
 * → 修改再触发打码 → start/finish/cancel/restore 全状态流转 → 恢复后重新走完取镜
 * → 提交异步批量核对任务（后台线程跑）→ 定时清理到期任务。
 * </pre>
 * 全程断言：响应头回带 X-Trace-Id；异步线程继承提交请求 traceId；定时任务自带
 * sched- 前缀 traceId；每行日志统一带 [traceId] [orderNo] [jobNo]，按加工单号
 * 一把 grep 出该单在请求线程＋后台线程的全部日志；手机号/姓名入日志前已打码。
 * 词库为落盘文件（application-test.yml 指定），本类 @BeforeAll 写入，自给自足。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TraceLogIntegrationTest.TestShiroBypass.class)
class TraceLogIntegrationTest {

    @TestConfiguration
    static class TestShiroBypass {
        @Bean
        ShiroFilterChainDefinition shiroFilterChainDefinition() {
            DefaultShiroFilterChainDefinition chain = new DefaultShiroFilterChainDefinition();
            chain.addPathDefinition("/**", "anon");
            return chain;
        }
    }

    private static final Path DICT = Paths.get("./target/test-dict/sensitive-words.txt");
    private static final String DICT_CONTENT =
            "# 测试词库\n"
                    + "测试违禁词|BLOCK\n"
                    + "测试打码词|MASK\n"
                    + "vip|MASK\n";

    /** 统一日志格式文件（logback-spring.xml 的 FILE appender） */
    private static final Path LOG_FILE = Paths.get("logs/evops.log");

    /** 日志行格式：时间 级别(右补齐5字符) [traceId] [orderNo] [jobNo] [线程] logger : 消息 */
    private static final Pattern LOG_LINE = Pattern.compile(
            "^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d{3} (INFO|WARN|ERROR)\\s+"
                    + "\\[(.+)\\] \\[(.+)\\] \\[(.+)\\] \\[.+\\] [\\w.]+ : .+$");
    private static final Pattern SCHED_TRACE = Pattern.compile("sched-\\d{14}-[0-9a-f]{16}");

    @Resource
    private MockMvc mockMvc;
    @Resource
    private ObjectMapper objectMapper;
    @Resource
    private JdbcTemplate jdbcTemplate;
    @Resource
    private SensitiveWordManager wordManager;
    @Resource
    private BatchJobMaintenance maintenance;

    /** 与其他测试类共享内存库，请求号/单号全部带 TRACE 前缀且自增，避免撞唯一约束 */
    private static final AtomicLong REQ_SEQ = new AtomicLong(9000);

    @BeforeAll
    static void writeDict() throws IOException {
        Files.createDirectories(DICT.getParent());
        Files.write(DICT, DICT_CONTENT.getBytes(StandardCharsets.UTF_8));
    }

    @BeforeEach
    void reloadDict() {
        wordManager.reload();
    }

    // ---------------- 响应头回带 traceId ----------------

    @Test
    void trace_id_echoed_in_response_header_and_honored_from_upstream() throws Exception {
        // 未带请求头：生成 trace- 前缀新号并回带
        MvcResult generated = mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk()).andReturn();
        String traceId = generated.getResponse().getHeader("X-Trace-Id");
        assertNotNull(traceId, "响应头必须回带 X-Trace-Id");
        assertTrue(traceId.startsWith("trace-"), "未透传时应生成 trace- 前缀新号，实际：" + traceId);

        // 上游透传：原样沿用并回带（网关联调场景）
        mockMvc.perform(get("/api/health").header("X-Trace-Id", "upstream-abc-123"))
                .andExpect(status().isOk())
                .andExpect(result -> assertEquals("upstream-abc-123",
                        result.getResponse().getHeader("X-Trace-Id")));

        // 注入防护：含换行的恶意 traceId 被清洗，响应头不夹带换行伪造日志
        MvcResult evil = mockMvc.perform(get("/api/health")
                        .header("X-Trace-Id", "bad-trace\nFAKE-LOG-LINE"))
                .andExpect(status().isOk()).andReturn();
        String cleaned = evil.getResponse().getHeader("X-Trace-Id");
        assertNotNull(cleaned);
        assertFalse(cleaned.contains("\n"), "traceId 换行必须被清洗，防日志注入");
        assertTrue(cleaned.contains("_"), "控制字符应替换为下划线，实际：" + cleaned);
    }

    // ---------------- 最绕样例：敏感词拦截/打码 + 全状态流转 + 异步核对 + 按单号聚合 ----------------

    @Test
    void full_trace_aggregation_across_request_async_and_order_no() throws Exception {
        long offset = logOffset();
        long lensId = createLens("L-TRACE-1");

        // 1) 拦截级敏感词：整单拒绝，留痕独立事务不丢
        String blockBody = orderBody("O-TRACE-BLOCK-1", lensId, "李四", "13911112222",
                "备注里有测试违禁词", "S-TRACE", "-1.00", "-1.00");
        MvcResult blocked = mockMvc.perform(post("/api/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", "9101").header("X-Request-No", nextReq())
                        .content(blockBody))
                .andExpect(jsonPath("$.code").value("SENSITIVE_WORD_BLOCKED"))
                .andReturn();
        assertNotNull(blocked.getResponse().getHeader("X-Trace-Id"), "失败响应同样回带 traceId");
        Integer blockedLogs = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_sensitive_scan_log WHERE order_no='O-TRACE-BLOCK-1' AND action='BLOCK'",
                Integer.class);
        assertEquals(1, blockedLogs.intValue(), "BLOCK 拦截尝试必须独立事务留痕");

        // 2) 打码级敏感词走最绕写法：全角 VIP＋插空"测 试-打 码-词"，归一化后命中 MASK，打码放行
        String maskBody = orderBody("O-TRACE-MASK-2", lensId, "张三丰", "13812345678",
                "客户是ＶＩＰ，备注测 试-打 码-词哦", "S-TRACE", "-3.25", "-2.50");
        MvcResult created = mockMvc.perform(post("/api/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", "9102").header("X-Request-No", nextReq())
                        .content(maskBody))
                .andExpect(jsonPath("$.code").value("OK"))
                .andReturn();
        JsonNode createdData = objectMapper.readTree(created.getResponse().getContentAsString()).get("data");
        long orderId = createdData.get("id").asLong();
        long version = createdData.get("versionNo").asLong();
        String storedRemark = jdbcTemplate.queryForObject(
                "SELECT remark FROM t_process_order WHERE id=?", String.class, orderId);
        assertFalse(storedRemark.contains("测试打码词"), "MASK 命中区间必须打码落库，实际：" + storedRemark);
        assertTrue(storedRemark.contains("*"), "打码后应含 *，实际：" + storedRemark);

        // 3) 修改：再次带打码词，处方整组替换
        String updateBody = "{\"id\":" + orderId + ",\"versionNo\":" + version + ","
                + "\"remark\":\"改后还有测试打码词\","
                + "\"prescriptions\":["
                + "{\"eye\":\"L\",\"sphere\":-3.50,\"cylinder\":-0.50,\"axis\":90},"
                + "{\"eye\":\"R\",\"sphere\":-2.75}]}";
        mockMvc.perform(put("/api/orders").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", "9103").header("X-Request-No", nextReq())
                        .content(updateBody))
                .andExpect(jsonPath("$.code").value("OK"));

        // 4) 全状态流转：start→finish→cancel→restore→start→finish→pickup（最绕：冲销恢复后重走）
        act(orderId, "start", "PROCESSING");
        act(orderId, "finish", "READY");
        act(orderId, "cancel", "CANCELLED");
        act(orderId, "restore", "CREATED");
        act(orderId, "start", "PROCESSING");
        act(orderId, "finish", "READY");
        act(orderId, "pickup", "PICKED_UP");
        // 已取镜不可冲销
        mockMvc.perform(post("/api/orders/" + orderId + "/cancel")
                        .header("X-Operator-Id", "9104").header("X-Request-No", nextReq()))
                .andExpect(jsonPath("$.code").value("ORDER_PICKED_UP"));

        // 5) 历史直插数据（无写路径留痕）：进 neverScanned
        jdbcTemplate.update("INSERT INTO t_process_order (order_no, customer_name, store_code, lens_id,"
                + " order_status, request_no) VALUES ('O-TRACE-RAW-1','直插客户','S-TRACE',"
                + lensId + ",'CREATED','" + nextReq() + "')");

        // 6) 提交异步批量核对任务：响应头 traceId 即后台线程应继承的链路号
        MvcResult submitted = mockMvc.perform(post("/api/batch/jobs")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", "9105").header("X-Request-No", nextReq())
                        .content("{\"jobType\":\"RECHECK\",\"storeCode\":\"S-TRACE\"}"))
                .andExpect(jsonPath("$.code").value("OK"))
                .andReturn();
        String submitTraceId = submitted.getResponse().getHeader("X-Trace-Id");
        assertNotNull(submitTraceId);
        String jobNo = objectMapper.readTree(submitted.getResponse().getContentAsString())
                .get("data").get("jobNo").asText();

        JsonNode terminal = waitForStatus(jobNo, "SUCCEEDED", 15_000);
        JsonNode report = terminal.get("result");
        assertTrue(contains(report.get("neverScanned"), "O-TRACE-RAW-1"), "直插数据应进 neverScanned");
        assertEquals(2, report.get("matchedFields").asInt(), "打码单两字段重扫 PASS 不属处置加重");

        // 7) 日志聚合断言（只读本测试增量，避免历史运行干扰）
        String logs = readLogsSince(offset);
        assertFalse(logs.isEmpty(), "日志文件应有输出，请确认 logback-spring.xml 生效");

        // 7a) 异步传递：后台线程的"任务开始/完毕"日志带提交请求的 traceId 与 jobNo
        assertLine(logs, "批量任务开始执行", submitTraceId, null, jobNo);
        assertLine(logs, "批量任务执行完毕", submitTraceId, null, jobNo);

        // 7b) 按单号一键聚合：同一加工单在请求线程＋后台线程的日志都能用 [O-TRACE-MASK-2] 捞出
        String[] orderLines = linesContaining(logs, "[O-TRACE-MASK-2]");
        assertTrue(orderLines.length >= 8,
                "建档/修改/7次流转至少 8 行日志应带加工单号，实际 " + orderLines.length + " 行");
        // 后台核对线程处理该单时同样带单号（recheck 单单独立事务的日志行）
        assertTrue(containsOrderNoInAsyncThread(logs, "O-TRACE-MASK-2", submitTraceId),
                "后台线程处理加工单时应继承提交请求 traceId 并带单号");

        // 7c) 拦截单：BLOCK 告警日志带单号；留痕落库已验证
        assertLine(logs, "命中拦截级敏感词", null, "O-TRACE-BLOCK-1", null);

        // 7d) 敏感字段打码：日志里只见 138****5678 / 张*丰，不见原文
        assertTrue(logs.contains("138****5678"), "手机号应打码后入日志");
        assertFalse(logs.contains("13812345678"), "手机号原文不得出现在日志");
        assertTrue(logs.contains("张*丰"), "姓名应打码后入日志");
        assertFalse(logs.contains("张三丰"), "姓名原文不得出现在日志");

        // 7e) 直插单核对日志也带单号
        assertLine(logs, "无写路径扫描留痕", submitTraceId, "O-TRACE-RAW-1", jobNo);

        // 7f) 日志格式统一：本测试产生的业务日志行三段 MDC 齐全
        assertLogFormat(orderLines);
    }

    // ---------------- 定时任务 traceId ----------------

    @Test
    void scheduled_purge_runs_with_generated_trace_id() throws Exception {
        // 造一个已到期的终态任务（保留期 21 天，这里直接过期）
        jdbcTemplate.update("INSERT INTO t_batch_job (job_no, job_type, job_status, expire_time, request_no)"
                        + " VALUES ('RECHECK-EXPIRED-T1','RECHECK','SUCCEEDED',"
                        + " DATEADD('DAY', -1, CURRENT_TIMESTAMP), ?)",
                nextReq());

        long offset = logOffset();
        // 直接调用定时任务入口本身：验证真实定时路径（含 sched- 前缀 traceId 绑定）
        maintenance.scheduledPurge();
        Integer remaining = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM t_batch_job WHERE job_no='RECHECK-EXPIRED-T1'", Integer.class);
        assertEquals(0, remaining.intValue(), "到期终态任务应被物理清理");

        String logs = readLogsSince(offset);
        String[] lines = linesContaining(logs, "物理删除到期任务");
        assertTrue(lines.length > 0, "定时清理应有日志输出");
        assertTrue(SCHED_TRACE.matcher(lines[0]).find(),
                "定时任务日志应自带 sched- 前缀 traceId，实际行：" + lines[0]);
    }

    // ---------------- 辅助方法 ----------------

    private String nextReq() {
        return "TRACE-REQ-" + REQ_SEQ.incrementAndGet();
    }

    private long createLens(String code) throws Exception {
        String body = "{\"lensCode\":\"" + code + "\",\"lensName\":\"链路测试片\",\"price\":399.00}";
        MvcResult result = mockMvc.perform(post("/api/lens")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Operator-Id", "9100").header("X-Request-No", nextReq())
                        .content(body))
                .andExpect(jsonPath("$.code").value("OK")).andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("data").get("id").asLong();
    }

    private String orderBody(String orderNo, long lensId, String customer, String phone,
                             String remark, String storeCode, String lSphere, String rSphere) {
        return "{\"orderNo\":\"" + orderNo + "\",\"lensId\":" + lensId
                + ",\"customerName\":\"" + customer + "\",\"customerPhone\":\"" + phone + "\""
                + ",\"storeCode\":\"" + storeCode + "\",\"remark\":\"" + remark + "\""
                + ",\"prescriptions\":["
                + "{\"eye\":\"L\",\"sphere\":" + lSphere + "},"
                + "{\"eye\":\"R\",\"sphere\":" + rSphere + "}]}";
    }

    private void act(long orderId, String action, String expectedStatus) throws Exception {
        mockMvc.perform(post("/api/orders/" + orderId + "/" + action)
                        .header("X-Operator-Id", "9106").header("X-Request-No", nextReq()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("OK"))
                .andExpect(jsonPath("$.data.orderStatus").value(expectedStatus));
    }

    private JsonNode waitForStatus(String jobNo, String expected, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            MvcResult result = mockMvc.perform(get("/api/batch/jobs/" + jobNo))
                    .andExpect(status().isOk()).andReturn();
            JsonNode data = objectMapper.readTree(result.getResponse().getContentAsString()).get("data");
            String status = data.get("jobStatus").asText();
            if (expected.equals(status)) {
                return data;
            }
            if ("FAILED".equals(status) || "CANCELLED".equals(status)) {
                fail("任务进入意外终态 " + status + "：" + data);
            }
            Thread.sleep(50);
        }
        fail("等待任务 " + jobNo + " 到达 " + expected + " 超时");
        return null;
    }

    private boolean contains(JsonNode array, String value) {
        if (array == null || !array.isArray()) {
            return false;
        }
        for (JsonNode node : array) {
            if (value.equals(node.asText())) {
                return true;
            }
        }
        return false;
    }

    // ---------------- 日志文件断言辅助 ----------------

    private long logOffset() throws IOException {
        return Files.exists(LOG_FILE) ? Files.size(LOG_FILE) : 0;
    }

    private String readLogsSince(long offset) throws IOException {
        if (!Files.exists(LOG_FILE)) {
            return "";
        }
        byte[] bytes = Files.readAllBytes(LOG_FILE);
        if (offset >= bytes.length) {
            return "";
        }
        return new String(bytes, (int) offset, bytes.length - (int) offset, StandardCharsets.UTF_8);
    }

    private String[] linesContaining(String logs, String token) {
        return java.util.Arrays.stream(logs.split("\\R"))
                .filter(line -> line.contains(token))
                .toArray(String[]::new);
    }

    /**
     * 断言存在一行日志：含 messageToken，且 traceId/orderNo/jobNo 三段 MDC 与期望值一致
     * （期望值为 null 表示该段不校验）。
     */
    private void assertLine(String logs, String messageToken,
                            String traceId, String orderNo, String jobNo) {
        for (String line : logs.split("\\R")) {
            if (!line.contains(messageToken)) {
                continue;
            }
            java.util.regex.Matcher m = LOG_LINE.matcher(line);
            if (!m.matches()) {
                continue;
            }
            if (traceId != null && !traceId.equals(m.group(2))) {
                continue;
            }
            if (orderNo != null && !orderNo.equals(m.group(3))) {
                continue;
            }
            if (jobNo != null && !jobNo.equals(m.group(4))) {
                continue;
            }
            return; // 找到
        }
        fail("未找到日志行：消息含[" + messageToken + "] traceId=" + traceId
                + " orderNo=" + orderNo + " jobNo=" + jobNo);
    }

    /** 后台线程处理指定加工单时：日志行同时带该单号与提交请求的 traceId */
    private boolean containsOrderNoInAsyncThread(String logs, String orderNo, String traceId) {
        for (String line : logs.split("\\R")) {
            java.util.regex.Matcher m = LOG_LINE.matcher(line);
            if (m.matches() && orderNo.equals(m.group(3)) && traceId.equals(m.group(2))) {
                return true;
            }
        }
        return false;
    }

    /** 统一格式校验：每行匹配"时间 级别 [traceId] [orderNo] [jobNo] [线程] logger : 消息" */
    private void assertLogFormat(String[] lines) {
        assertTrue(lines.length > 0);
        for (String line : lines) {
            assertTrue(LOG_LINE.matcher(line).matches(), "日志行不符合统一格式：" + line);
        }
    }
}
