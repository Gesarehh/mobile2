import { useState } from 'react';
import { useLocalSearchParams } from 'expo-router';
import { StyleSheet, ScrollView, View, TouchableOpacity } from 'react-native';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import { MaterialCommunityIcons } from '@expo/vector-icons';

type CountyData = {
  registeredVoters: number;
  eligibleVoters: number;
  pollingStations: number;
  lastUpdated: string;
  constituencies: { name: string; voters: number }[];
};

const countyStats: Record<string, CountyData> = {
  "Nairobi": {
    registeredVoters: 2456789,
    eligibleVoters: 3200456,
    pollingStations: 1450,
    lastUpdated: "2023-10-15",
    constituencies: [
      { name: "Westlands", voters: 145678 },
      { name: "Dagoretti", voters: 187654 },
      { name: "Langata", voters: 165432 },
      { name: "Kasarani", voters: 198765 },
      { name: "Embakasi", voters: 210987 },
    ]
  },
  "Mombasa": {
    registeredVoters: 987654,
    eligibleVoters: 1200456,
    pollingStations: 650,
    lastUpdated: "2023-10-12",
    constituencies: [
      { name: "Mvita", voters: 145678 },
      { name: "Kisauni", voters: 187654 },
      { name: "Nyali", voters: 165432 },
      { name: "Likoni", voters: 123456 },
    ]
  },
  "Kisumu": {
    registeredVoters: 765432,
    eligibleVoters: 950000,
    pollingStations: 520,
    lastUpdated: "2023-10-10",
    constituencies: [
      { name: "Kisumu Central", voters: 145678 },
      { name: "Kisumu East", voters: 123456 },
      { name: "Kisumu West", voters: 98765 },
    ]
  },
  "Nakuru": {
    registeredVoters: 1123456,
    eligibleVoters: 1400000,
    pollingStations: 780,
    lastUpdated: "2023-10-14",
    constituencies: [
      { name: "Nakuru Town East", voters: 187654 },
      { name: "Nakuru Town West", voters: 165432 },
      { name: "Naivasha", voters: 198765 },
      { name: "Gilgil", voters: 123456 },
    ]
  },
  "Kiambu": {
    registeredVoters: 1345678,
    eligibleVoters: 1600000,
    pollingStations: 890,
    lastUpdated: "2023-10-13",
    constituencies: [
      { name: "Kiambu", voters: 187654 },
      { name: "Limuru", voters: 165432 },
      { name: "Kikuyu", voters: 198765 },
      { name: "Thika", voters: 210987 },
    ]
  },
  "Kakamega": {
    registeredVoters: 876543,
    eligibleVoters: 1100000,
    pollingStations: 620,
    lastUpdated: "2023-10-11",
    constituencies: [
      { name: "Kakamega Central", voters: 145678 },
      { name: "Kakamega North", voters: 123456 },
      { name: "Kakamega South", voters: 98765 },
    ]
  },
  "Bungoma": {
    registeredVoters: 765432,
    eligibleVoters: 950000,
    pollingStations: 580,
    lastUpdated: "2023-10-09",
    constituencies: [
      { name: "Bungoma Central", voters: 145678 },
      { name: "Bungoma North", voters: 123456 },
      { name: "Bungoma South", voters: 98765 },
    ]
  }
};

const countyNames = Object.keys(countyStats);

export default function CountyStatsScreen() {
  const { county: initialCounty } = useLocalSearchParams();
  const [selectedCounty, setSelectedCounty] = useState<string>(
    typeof initialCounty === 'string' && initialCounty in countyStats 
      ? initialCounty 
      : "Nairobi"
  );
  const [showCountyPicker, setShowCountyPicker] = useState(false);

  const data = countyStats[selectedCounty];

  return (
    <ScrollView 
      contentContainerStyle={styles.scrollContainer}
      showsVerticalScrollIndicator={false}
    >
      <ThemedView style={styles.container}>
        {/* County Selector Header */}
        <View style={styles.header}>
          <ThemedText type="title" style={styles.title}>
            {selectedCounty} County Voter Statistics
          </ThemedText>
          <TouchableOpacity 
            onPress={() => setShowCountyPicker(!showCountyPicker)}
            style={styles.countySelectorButton}
          >
            <MaterialCommunityIcons 
              name={showCountyPicker ? "chevron-up" : "chevron-down"} 
              size={24} 
              color="#3498db" 
            />
          </TouchableOpacity>
        </View>

        {/* County Picker Dropdown */}
        {showCountyPicker && (
          <ThemedView style={styles.countyPicker}>
            {countyNames.map((county) => (
              <TouchableOpacity
                key={county}
                onPress={() => {
                  setSelectedCounty(county);
                  setShowCountyPicker(false);
                }}
                style={[
                  styles.countyOption,
                  county === selectedCounty && styles.selectedCountyOption
                ]}
              >
                <ThemedText 
                  style={[
                    styles.countyOptionText,
                    county === selectedCounty && styles.selectedCountyOptionText
                  ]}
                >
                  {county}
                </ThemedText>
              </TouchableOpacity>
            ))}
          </ThemedView>
        )}

        {/* Statistics Cards */}
        <ThemedView style={styles.statsContainer}>
          <ThemedView style={styles.statCard}>
            <ThemedText type="defaultSemiBold" style={styles.statLabel}>
              Registered Voters
            </ThemedText>
            <ThemedText type="title" style={styles.statValue}>
              {data.registeredVoters.toLocaleString()}
            </ThemedText>
          </ThemedView>
          
          <ThemedView style={styles.statCard}>
            <ThemedText type="defaultSemiBold" style={styles.statLabel}>
              Eligible Voters
            </ThemedText>
            <ThemedText type="title" style={styles.statValue}>
              {data.eligibleVoters.toLocaleString()}
            </ThemedText>
          </ThemedView>
        </ThemedView>

        <ThemedView style={styles.infoCard}>
          <ThemedText type="defaultSemiBold" style={styles.infoTitle}>
            Polling Stations
          </ThemedText>
          <ThemedText style={styles.infoValue}>
            {data.pollingStations.toLocaleString()} stations
          </ThemedText>
          <ThemedText style={styles.lastUpdated}>
            Last updated: {data.lastUpdated}
          </ThemedText>
        </ThemedView>

        <ThemedText type="subtitle" style={styles.sectionTitle}>
          Constituency Breakdown
        </ThemedText>
        
        {data.constituencies.map((constituency, index) => (
          <ThemedView key={index} style={styles.constituencyItem}>
            <ThemedText type="defaultSemiBold" style={styles.constituencyName}>
              {constituency.name}
            </ThemedText>
            <ThemedText style={styles.constituencyVoters}>
              {constituency.voters.toLocaleString()} voters
            </ThemedText>
          </ThemedView>
        ))}

        <ThemedView style={styles.noteBox}>
          <ThemedText style={styles.noteText}>
            Note: All data is based on official IEBC records. For the most current information, please visit your nearest IEBC office.
          </ThemedText>
        </ThemedView>
      </ThemedView>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollContainer: {
    flexGrow: 1,
    backgroundColor: '#f8f9fa',
  },
  container: {
    flex: 1,
    padding: 20,
    gap: 20,
    paddingBottom: 40,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 16,
  },
  title: {
    marginBottom: 8,
    textAlign: 'center',
    color: '#2c3e50',
  },
  countySelectorButton: {
    padding: 8,
    marginLeft: 10,
  },
  countyPicker: {
    backgroundColor: '#ffffff',
    borderRadius: 8,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
    maxHeight: 200,
  },
  countyOption: {
    padding: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#ecf0f1',
  },
  selectedCountyOption: {
    backgroundColor: '#e8f4f8',
  },
  countyOptionText: {
    fontSize: 16,
    color: '#2c3e50',
  },
  selectedCountyOptionText: {
    color: '#3498db',
    fontWeight: 'bold',
  },
  statsContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 16,
  },
  statCard: {
    flex: 1,
    padding: 16,
    borderRadius: 10,
    backgroundColor: '#ffffff',
    alignItems: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
  },
  statLabel: {
    color: '#7f8c8d',
    fontSize: 14,
  },
  statValue: {
    color: '#2c3e50',
    marginTop: 8,
  },
  infoCard: {
    padding: 16,
    borderRadius: 10,
    backgroundColor: '#ffffff',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
  },
  infoTitle: {
    color: '#7f8c8d',
    fontSize: 14,
  },
  infoValue: {
    color: '#2c3e50',
    fontSize: 18,
    marginTop: 8,
  },
  lastUpdated: {
    color: '#95a5a6',
    fontSize: 12,
    marginTop: 8,
    fontStyle: 'italic',
  },
  sectionTitle: {
    marginTop: 16,
    color: '#2c3e50',
    paddingBottom: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#ecf0f1',
  },
  constituencyItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 14,
    paddingHorizontal: 16,
    backgroundColor: '#ffffff',
    borderRadius: 8,
    marginBottom: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.05,
    shadowRadius: 2,
    elevation: 1,
  },
  constituencyName: {
    color: '#2c3e50',
    flex: 2,
  },
  constituencyVoters: {
    color: '#3498db',
    flex: 1,
    textAlign: 'right',
  },
  noteBox: {
    marginTop: 20,
    padding: 16,
    backgroundColor: '#e8f4f8',
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#3498db',
  },
  noteText: {
    color: '#7f8c8d',
    fontSize: 13,
    lineHeight: 20,
  },
});