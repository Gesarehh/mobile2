import React, { useState } from 'react';
import { StyleSheet, View, Dimensions, TouchableOpacity, Linking, ScrollView } from 'react-native';
import MapView, { Marker, Callout } from 'react-native-maps';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import { Button } from 'react-native-paper';
import { FontAwesome } from '@expo/vector-icons';


const pollingStations = [
    {
      id: 1,
      name: "Nairobi Primary School",
      location: "City Centre",
      coordinates: {
        latitude: -1.286389,
        longitude: 36.817223,
      },
      registeredVoters: 2456,
      eligibleVoters: 3200,
      contact: "020 1234567",
    },
    {
      id: 2,
      name: "Uhuru Park Polling Centre",
      location: "Opposite KICC",
      coordinates: {
        latitude: -1.2931,
        longitude: 36.8219,
      },
      registeredVoters: 1876,
      eligibleVoters: 2500,
      contact: "020 7654321",
    },
    {
      id: 3,
      name: "Kasarani Sports Centre",
      location: "Moi International Sports Centre",
      coordinates: {
        latitude: -1.2195,
        longitude: 36.8963,
      },
      registeredVoters: 3210,
      eligibleVoters: 4200,
      contact: "020 9876543",
    },
    {
      id: 4,
      name: "Mombasa Polytechnic",
      location: "Mombasa Island",
      coordinates: {
        latitude: -4.0435,
        longitude: 39.6682,
      },
      registeredVoters: 1987,
      eligibleVoters: 2600,
      contact: "041 1234567",
    },
    {
      id: 5,
      name: "Kisumu Boys High School",
      location: "Kisumu Central",
      coordinates: {
        latitude: -0.0917,
        longitude: 34.7680,
      },
      registeredVoters: 1765,
      eligibleVoters: 2300,
      contact: "057 2345678",
    },
    {
      id: 6,
      name: "Nakuru High School",
      location: "Nakuru Town",
      coordinates: {
        latitude: -0.2833,
        longitude: 36.0667,
      },
      registeredVoters: 2109,
      eligibleVoters: 2800,
      contact: "051 3456789",
    },
    {
      id: 7,
      name: "Eldoret Polytechnic",
      location: "Eldoret Town",
      coordinates: {
        latitude: 0.5204,
        longitude: 35.2699,
      },
      registeredVoters: 2345,
      eligibleVoters: 3100,
      contact: "053 4567890",
    },
    {
      id: 8,
      name: "Kakamega Primary School",
      location: "Kakamega Town",
      coordinates: {
        latitude: 0.2827,
        longitude: 34.7519,
      },
      registeredVoters: 1654,
      eligibleVoters: 2200,
      contact: "056 5678901",
    },
    {
      id: 9,
      name: "Machakos Girls High School",
      location: "Machakos Town",
      coordinates: {
        latitude: -1.5221,
        longitude: 37.2658,
      },
      registeredVoters: 1432,
      eligibleVoters: 1900,
      contact: "044 6789012",
    },
    {
      id: 10,
      name: "Meru National Polytechnic",
      location: "Meru Town",
      coordinates: {
        latitude: 0.0519,
        longitude: 37.6456,
      },
      registeredVoters: 1876,
      eligibleVoters: 2500,
      contact: "064 7890123",
    },
    {
      id: 11,
      name: "Thika High School",
      location: "Thika Town",
      coordinates: {
        latitude: -1.0396,
        longitude: 37.0833,
      },
      registeredVoters: 1987,
      eligibleVoters: 2600,
      contact: "067 8901234",
    },
    {
      id: 12,
      name: "Nyeri High School",
      location: "Nyeri Town",
      coordinates: {
        latitude: -0.4201,
        longitude: 36.9476,
      },
      registeredVoters: 1765,
      eligibleVoters: 2300,
      contact: "061 9012345",
    },
    {
      id: 13,
      name: "Garissa Primary School",
      location: "Garissa Town",
      coordinates: {
        latitude: -0.4536,
        longitude: 39.6461,
      },
      registeredVoters: 1543,
      eligibleVoters: 2100,
      contact: "046 0123456",
    },
    {
      id: 14,
      name: "Embu University",
      location: "Embu Town",
      coordinates: {
        latitude: -0.5390,
        longitude: 37.4574,
      },
      registeredVoters: 1321,
      eligibleVoters: 1800,
      contact: "068 1234567",
    },
    {
      id: 15,
      name: "Kitui High School",
      location: "Kitui Town",
      coordinates: {
        latitude: -1.3667,
        longitude: 38.0167,
      },
      registeredVoters: 1210,
      eligibleVoters: 1700,
      contact: "044 2345678",
    },
    {
      id: 16,
      name: "Malindi Secondary School",
      location: "Malindi Town",
      coordinates: {
        latitude: -3.2176,
        longitude: 40.1191,
      },
      registeredVoters: 1876,
      eligibleVoters: 2500,
      contact: "042 3456789",
    },
    {
      id: 17,
      name: "Kitale Primary School",
      location: "Kitale Town",
      coordinates: {
        latitude: 1.0167,
        longitude: 35.0000,
      },
      registeredVoters: 1654,
      eligibleVoters: 2200,
      contact: "054 4567890",
    },
    {
      id: 18,
      name: "Bungoma High School",
      location: "Bungoma Town",
      coordinates: {
        latitude: 0.5695,
        longitude: 34.5584,
      },
      registeredVoters: 1432,
      eligibleVoters: 1900,
      contact: "055 5678901",
    },
    {
      id: 19,
      name: "Homa Bay High School",
      location: "Homa Bay Town",
      coordinates: {
        latitude: -0.5273,
        longitude: 34.4571,
      },
      registeredVoters: 1321,
      eligibleVoters: 1800,
      contact: "059 6789012",
    },
    {
      id: 20,
      name: "Busia Polytechnic",
      location: "Busia Town",
      coordinates: {
        latitude: 0.4600,
        longitude: 34.1117,
      },
      registeredVoters: 1210,
      eligibleVoters: 1700,
      contact: "056 7890123",
    }
  ];

  export default function PollingStationScreen() {
    const [selectedStation, setSelectedStation] = useState<typeof pollingStations[0] | null>(null);
  
    const handleCallStation = (phoneNumber: string): void => {
      Linking.openURL(`tel:${phoneNumber}`);
    };
  
    return (
      <ScrollView contentContainerStyle={styles.scrollContainer}>
        <ThemedView style={styles.container}>
          <ThemedText type="title" style={styles.title}>Polling Stations</ThemedText>
          <ThemedText style={styles.subtitle}>Tap on a marker to see station details (Zoom out kindly)</ThemedText>
  
          <View style={styles.mapContainer}>
            <MapView
              style={styles.map}
              initialRegion={{
                latitude: -1.286389,
                longitude: 36.817223,
                latitudeDelta: 0.0922,
                longitudeDelta: 0.0421,
              }}
            >
              {pollingStations.map((station) => (
                <Marker
                  key={station.id}
                  coordinate={station.coordinates}
                  onPress={() => setSelectedStation(station)}
                >
                  <Callout tooltip style={styles.callout}>
                    <ThemedView style={styles.calloutContainer}>
                      <ThemedText type="subtitle">{station.name}</ThemedText>
                      <ThemedText>{station.location}</ThemedText>
                      <View style={styles.divider} />
                      <ThemedText>Registered Voters: {station.registeredVoters.toLocaleString()}</ThemedText>
                      <ThemedText>Eligible Voters: {station.eligibleVoters.toLocaleString()}</ThemedText>
                      <ThemedText>
                        Registration Rate: {Math.round((station.registeredVoters / station.eligibleVoters) * 100)}%
                      </ThemedText>
                      <Button 
                        mode="contained" 
                        icon="phone" 
                        style={styles.callButton}
                        onPress={() => handleCallStation(station.contact)}
                      >
                        Call Station
                      </Button>
                    </ThemedView>
                  </Callout>
                </Marker>
              ))}
            </MapView>
          </View>
  
          {selectedStation && (
            <ThemedView style={styles.detailsPanel}>
              <ThemedText type="subtitle">{selectedStation.name}</ThemedText>
              <ThemedText>{selectedStation.location}</ThemedText>
              
              <View style={styles.statsContainer}>
                <View style={styles.statItem}>
                  <FontAwesome name="user" size={20} color="#006400" />
                  <ThemedText style={styles.statText}>
                    {selectedStation.registeredVoters.toLocaleString()} registered
                  </ThemedText>
                </View>
                <View style={styles.statItem}>
                  <FontAwesome name="users" size={20} color="#006400" />
                  <ThemedText style={styles.statText}>
                    {selectedStation.eligibleVoters.toLocaleString()} eligible
                  </ThemedText>
                </View>
              </View>
  
              <View style={styles.progressContainer}>
                <View style={[
                  styles.progressBar,
                  { 
                    width: `${Math.min(
                      (selectedStation.registeredVoters / selectedStation.eligibleVoters) * 100, 
                      100
                    )}%` 
                  }
                ]} />
                <ThemedText style={styles.progressText}>
                  {Math.round((selectedStation.registeredVoters / selectedStation.eligibleVoters) * 100)}% registered
                </ThemedText>
              </View>
  
              <TouchableOpacity 
                style={styles.contactButton}
                onPress={() => handleCallStation(selectedStation.contact)}
              >
                <FontAwesome name="phone" size={20} color="white" />
                <ThemedText style={styles.contactButtonText}>Contact: {selectedStation.contact}</ThemedText>
              </TouchableOpacity>
            </ThemedView>
          )}
        </ThemedView>
      </ScrollView>
    );
  }
  
  const styles = StyleSheet.create({
    scrollContainer: {
      flexGrow: 1,
    },
    container: {
      flex: 1,
      padding: 16,
    },
    title: {
      marginBottom: 8,
    },
    subtitle: {
      marginBottom: 16,
      color: '#666',
    },
    mapContainer: {
      height: Dimensions.get('window').height / 2,
      marginBottom: 16,
    },
    map: {
      width: '100%',
      height: '100%',
      borderRadius: 10,
    },
    callout: {
      width: 250,
      padding: 0,
      borderRadius: 8,
    },
    calloutContainer: {
      padding: 12,
      gap: 6,
    },
    divider: {
      height: 1,
      backgroundColor: '#ddd',
      marginVertical: 8,
    },
    callButton: {
      marginTop: 8,
    },
    detailsPanel: {
      padding: 16,
      borderRadius: 10,
      backgroundColor: 'rgba(0, 0, 0, 0.03)',
      gap: 12,
    },
    statsContainer: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      marginTop: 8,
    },
    statItem: {
      flexDirection: 'row',
      alignItems: 'center',
      gap: 8,
    },
    statText: {
      fontSize: 16,
    },
    progressContainer: {
      height: 20,
      backgroundColor: '#f0f0f0',
      borderRadius: 10,
      marginTop: 8,
      overflow: 'hidden',
      justifyContent: 'center',
    },
    progressBar: {
      height: '100%',
      backgroundColor: '#4CAF50',
      borderRadius: 10,
    },
    progressText: {
      position: 'absolute',
      width: '100%',
      textAlign: 'center',
      color: 'white',
      fontSize: 12,
      fontWeight: 'bold',
    },
    contactButton: {
      flexDirection: 'row',
      backgroundColor: '#006400',
      padding: 12,
      borderRadius: 8,
      alignItems: 'center',
      justifyContent: 'center',
      gap: 10,
      marginTop: 12,
    },
    contactButtonText: {
      color: 'white',
      fontWeight: 'bold',
    },
  });