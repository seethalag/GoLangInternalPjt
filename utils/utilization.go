package utils

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
)

// UtilizationResponse defines the structure of the JSON response
type UtilizationResponse struct {
	CPUUtilization    float64 `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	StorageUtilization float64 `json:"storage_utilization"`
}

func GetUtilization(c *gin.Context) {
	// Get CPU utilization
	cpuUtil, err := cpu.Percent(time.Second, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch CPU utilization"})
		return
	}

	// Get Memory utilization
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch memory utilization"})
		return
	}

	// Get Storage utilization
	diskStat, err := disk.Usage("/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch storage utilization"})
		return
	}

	// Build the response
	utilResponse := UtilizationResponse{
		CPUUtilization:    cpuUtil[0],
		MemoryUtilization: vmStat.UsedPercent,
		StorageUtilization: diskStat.UsedPercent,
	}

	// Send response as JSON
	c.JSON(http.StatusOK, utilResponse)
}
