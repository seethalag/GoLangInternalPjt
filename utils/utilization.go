package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
)

// MetricsResponse represents the structure of the API response
type MetricsResponse struct {
	CPU struct {
		Usage float64 `json:"usage_percent"`
	} `json:"cpu"`
	Memory struct {
		UsedPercent float64 `json:"used_percent"`
		TotalGB     float64 `json:"total_gb"`
	} `json:"memory"`
	Storage struct {
		UsedPercent float64 `json:"used_percent"`
		TotalGB     float64 `json:"total_gb"`
	} `json:"storage"`
}

// GetSystemMetrics handles the `/metrics` endpoint
func GetSystemMetrics(c *gin.Context) {
	var response MetricsResponse

	// Fetch CPU usage
	cpuUsage, err := cpu.Percent(0, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch CPU usage"})
		return
	}
	response.CPU.Usage = cpuUsage[0]

	// Fetch Memory usage
	memStats, err := mem.VirtualMemory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch memory stats"})
		return
	}
	response.Memory.UsedPercent = memStats.UsedPercent
	response.Memory.TotalGB = float64(memStats.Total) / 1e9

	// Fetch Disk usage
	diskStats, err := disk.Usage("/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch disk stats"})
		return
	}
	response.Storage.UsedPercent = diskStats.UsedPercent
	response.Storage.TotalGB = float64(diskStats.Total) / 1e9

	// Return the metrics as JSON
	c.JSON(http.StatusOK, response)
}