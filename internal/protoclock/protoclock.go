// Package protoclock 是 SDK 内部唯一的系统时钟读取点。
//
// 公开 API 不暴露任何可替换时钟或时间注入点：角色 Workflow 在每次操作入口调用
// Now() 一次，然后把同一个值传给 pool/bitfs 的显式时间 helper，保证临界
// 过期点附近整次操作使用同一时间判断。它不是调用方可注入的扩展点。
package protoclock

import "time"

// Now 返回本次操作唯一使用的 UTC 时间。
func Now() time.Time { return time.Now().UTC() }
