// Package demoenv 负责加载各个 demo 共用的本地环境配置文件。
package demoenv

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Load 按优先顺序尝试读取环境文件：DEMO_ENV_FILE 指定的文件、仓库根目录
// 下的 demo/.env，以及从当前 demo 子目录回到上级目录时可能存在的 .env。
//
// 已经存在于进程环境中的变量优先级更高，因此 CI 或调用者显式 export 的值
// 可以覆盖本地文件。这里故意只支持简单的 KEY=VALUE 格式，不展开 shell
// 表达式，也不会把私钥等敏感值打印到日志中。
func Load() error {
	// 先收集候选路径，再逐个尝试。显式配置放在最前面，便于测试和特殊
	// 运行目录覆盖默认位置。
	candidates := []string{}
	if explicit := strings.TrimSpace(os.Getenv("DEMO_ENV_FILE")); explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates, "demo/.env", "../../.env")

	for _, candidate := range candidates {
		// Clean 只规范路径写法，不会改变文件内容；不存在的候选文件继续
		// 尝试下一个，其他 I/O 错误则必须直接返回。
		path := filepath.Clean(candidate)
		if err := loadFile(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		return nil
	}
	// 所有候选文件都不存在时，demo 仍可继续运行，后续代码会在真正需要
	// 某个配置时报告更具体的缺失变量。
	return nil
}

func loadFile(path string) error {
	// 使用普通文件读取而不是依赖第三方 dotenv 解析器，确保 demo 的配置
	// 语义简单、可预测，并且与仓库内的示例文件保持一致。
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		// 空行和以 # 开头的行是注释，不参与键值解析。
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Cut 只按第一个等号分割，因此 value 仍然可以包含等号；key
		// 为空或缺少等号都属于配置格式错误。
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return fmt.Errorf("invalid environment line %d in %s", lineNumber, path)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// 支持最常见的单引号/双引号包裹方式，但不模拟 shell 的转义和
		// 变量替换，避免把配置文件误解析成可执行脚本。
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		// LookupEnv 能区分“变量不存在”和“变量存在但值为空”。只要调用者
		// 已设置变量，就尊重调用者的值，包括显式设置的空字符串。
		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, value); err != nil {
				return fmt.Errorf("set %s from %s: %w", key, path, err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}
