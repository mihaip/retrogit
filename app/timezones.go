package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"time"
)

type TimezoneConfig struct {
	LocationNames []string
}

type Timezone struct {
	LocationName     string
	DisplayUTCOffset string
}

type Timezones []Timezone

func initTimezones() Timezones {
	configBytes, err := ioutil.ReadFile("config/timezones.json")
	if err != nil {
		log.Panicf("Could not read timezone config: %s", err.Error())
	}
	var config TimezoneConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Panicf("Could not parse timezones config %s: %s", configBytes, err.Error())
	}
	timezones = make(Timezones, 0, len(config.LocationNames))
	// Use a January date so that UTC offsets are not affected by DST in the northern hemisphere
	now := time.Unix(380937600, 0)
	for _, locationName := range config.LocationNames {
		if locationName == "" {
			timezones = append(timezones, Timezone{
				LocationName: locationName,
			})
			continue
		}
		location, err := time.LoadLocation(locationName)
		if err != nil {
			log.Printf("Location %s could not be loaded: %s", locationName, err.Error())
			continue
		}
		utcDelta := now.Sub(time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), location))
		utcDeltaHours := int(utcDelta.Hours())
		utcDeltaMinutes := int(utcDelta.Minutes()) - 60*utcDeltaHours
		timezones = append(timezones, Timezone{
			LocationName:     locationName,
			DisplayUTCOffset: fmt.Sprintf("%d:%02d", utcDeltaHours, utcDeltaMinutes),
		})
	}
	return timezones
}
