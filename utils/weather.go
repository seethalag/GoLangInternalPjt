package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// OpenWeatherMapResponse defines the structure of the API response from OpenWeatherMap
type OpenWeatherMapResponse struct {
	Main struct {
		Temp     float64 `json:"temp"`
		Humidity int     `json:"humidity"`
	} `json:"main"`
	Name string `json:"name"`
}

// WeatherResponse defines the structure of the API response we want to return
type WeatherResponse struct {
	City       string  `json:"city"`
	Temperature float64 `json:"temperature"`
	Humidity    int     `json:"humidity"`
}

// getWeather fetches the weather data from OpenWeatherMap
func GetWeather(city string) (*WeatherResponse, error) {
	apiKey := os.Getenv("WEATHER_API_KEY")
	url := fmt.Sprintf("http://api.openweathermap.org/data/2.5/weather?q=%s&appid=%s&units=metric", city, apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get weather data: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var weatherData OpenWeatherMapResponse
	err = json.Unmarshal(body, &weatherData)
	if err != nil {
		return nil, err
	}

	return &WeatherResponse{
		City:       weatherData.Name,
		Temperature: weatherData.Main.Temp,
		Humidity:    weatherData.Main.Humidity,
	}, nil
}

// weatherHandler handles HTTP requests for weather data
func WeatherHandler(c *gin.Context) {
	// Extract the "city" parameter from the route
	city := c.Param("city")

	// Call the GetWeather function to fetch weather data
	weatherData, err := GetWeather(city)
	if err != nil {
		// Respond with an error
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Respond with the weather data in JSON format
	c.JSON(http.StatusOK, weatherData)
}