package main

import (
	"context"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

var processStart = time.Now().UTC()

type OSMetrics struct {
	Hostname        string
	OSName          string
	OSVersion       string
	Kernel          string
	Arch            string
	CPUUsagePct     float64
	MemoryUsagePct  float64
	DiskUsagePct    float64
	Load1           float64
	UptimeSec       int64
	AgentRuntimeSec int64
}

func GatherOSMetrics(ctx context.Context) OSMetrics {
	out := OSMetrics{
		OSName:          runtime.GOOS,
		Arch:            runtime.GOARCH,
		AgentRuntimeSec: int64(time.Since(processStart).Seconds()),
	}

	if info, err := host.InfoWithContext(ctx); err == nil {
		out.Hostname = strings.TrimSpace(info.Hostname)
		out.OSName = firstNonEmpty(strings.TrimSpace(info.Platform), strings.TrimSpace(info.OS), out.OSName)
		out.OSVersion = strings.TrimSpace(info.PlatformVersion)
		out.Kernel = strings.TrimSpace(info.KernelVersion)
		out.UptimeSec = int64(info.Uptime)
	}

	if percent, err := cpu.PercentWithContext(ctx, 0, false); err == nil && len(percent) > 0 {
		out.CPUUsagePct = percent[0]
	}

	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		out.MemoryUsagePct = vm.UsedPercent
	}

	diskPath := "/"
	if runtime.GOOS == "windows" {
		diskPath = `C:\`
	}
	if du, err := disk.UsageWithContext(ctx, diskPath); err == nil {
		out.DiskUsagePct = du.UsedPercent
	}

	if runtime.GOOS != "windows" {
		if avg, err := load.AvgWithContext(ctx); err == nil {
			out.Load1 = avg.Load1
		}
	}
	return out
}
