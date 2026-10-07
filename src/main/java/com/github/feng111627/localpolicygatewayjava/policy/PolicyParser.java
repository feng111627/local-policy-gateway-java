package com.github.feng111627.localpolicygatewayjava.policy;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.feng111627.localpolicygatewayjava.model.Policy;
import org.springframework.stereotype.Component;

/**
 * 把策略 JSON 文本解析为 {@link Policy}。
 *
 * <p>错误必须可区分：
 * <ul>
 *   <li>JSON 词法/语法错误 → {@link PolicyError#SYNTAX_ERROR}；</li>
 *   <li>结构与 JSON 不匹配（未知枚举、类型错误、必填字段缺失等）→ {@link PolicyError#INVALID_VALUE}
 *       或 {@link PolicyError#MISSING_FIELD}，再由 {@link PolicyValidator} 做更细的语义校验。</li>
 * </ul>
 */
@Component
public class PolicyParser {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public Policy parse(String json) {
        if (json == null || json.isBlank()) {
            throw new PolicyParseException(PolicyError.SYNTAX_ERROR, "策略内容为空");
        }
        try {
            return objectMapper.readValue(json, Policy.class);
        } catch (JsonParseException e) {
            String location = e.getLocation() == null ? "" : "（位置 " + e.getLocation().getLineNr()
                    + ":" + e.getLocation().getColumnNr() + "）";
            throw new PolicyParseException(PolicyError.SYNTAX_ERROR,
                    "策略 JSON 语法错误" + location + ": " + e.getOriginalMessage());
        } catch (JsonMappingException e) {
            // JSON 能读出来，但结构/取值无法映射（如未知 effect 枚举、字段类型错误）
            throw new PolicyParseException(PolicyError.INVALID_VALUE,
                    "策略字段结构或取值非法: " + e.getOriginalMessage());
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new PolicyParseException(PolicyError.SYNTAX_ERROR, "策略无法解析: " + e.getOriginalMessage());
        }
    }
}
