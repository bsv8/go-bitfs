package seller

import "time"

// unixSeconds 把协议 UTC Unix 秒还原为 UTC time.Time（纯函数，无时钟读取）。
func unixSeconds(value int64) time.Time { return time.Unix(value, 0).UTC() }
