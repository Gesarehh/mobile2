import { StyleSheet, Platform, Linking } from 'react-native';
import { HelloWave } from '@/components/HelloWave';
import ParallaxScrollView from '@/components/ParallaxScrollView';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import { Image } from 'expo-image';
import { FontAwesome } from '@expo/vector-icons';
import { Button } from 'react-native-paper';
import MapView from 'react-native-maps';
import { router, Redirect } from 'expo-router';
import { useAuth } from '@/context/AuthContext';

const styles = StyleSheet.create({
  titleContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 16,
  },
  stepContainer: {
    gap: 12,
    marginBottom: 24,
  },
  kenyaFlag: {
    height: "100%",
    width: '100%',
    bottom: 0,
    position: 'absolute',
  },
  button: {
    marginTop: 12,
  },
  map: {
    width: '100%',
    height: 200,
    borderRadius: 8,
    marginTop: 12,
  },
});

export default function HomeScreen() {
  const { user } = useAuth();
  
  // Auth check - if no user, redirect to login
  if (!user) {
    return <Redirect href="/login" />;
  }
  
  // User interface functions
  const openIEBCWebsite = () => {
    Linking.openURL('https://www.iebc.or.ke');
  };

  // Render the actual content when user is authenticated
  return (
    <ParallaxScrollView
      headerBackgroundColor={{ light: '#A1CEDC', dark: '#1D3D47' }}
      headerImage={
        <Image
          source={require('@/assets/images/kenya.jpg')}
          style={styles.kenyaFlag}
          contentFit="contain"
        />
      }>
      <ThemedView style={styles.titleContainer}>
        <ThemedText type="title">Kenya Voter Eligibility</ThemedText>
        <HelloWave />
      </ThemedView>
      <ThemedView style={styles.stepContainer}>
        <ThemedText type="subtitle">Check Your Voting Status</ThemedText>
        <ThemedText>
          Verify if you're eligible to vote in the next Kenyan election.
        </ThemedText>
        <Button 
          mode="contained" 
          style={styles.button}
          onPress={() => router.push('/(tabs)/eligibility')}>
          Check Eligibility
        </Button>
      </ThemedView>
      <ThemedView style={styles.stepContainer}>
        <ThemedText type="subtitle">Find Polling Stations</ThemedText>
        <ThemedText>
          Locate your nearest polling station using our interactive map.
        </ThemedText>
        <MapView
          style={styles.map}
          initialRegion={{
            latitude: -0.0236,
            longitude: 37.9062,
            latitudeDelta: 15,
            longitudeDelta: 15,
          }}
        />
      </ThemedView>
      <ThemedView style={styles.stepContainer}>
        <ThemedText type="subtitle">IEBC Resources</ThemedText>
        <ThemedText>
          Visit the Independent Electoral and Boundaries Commission website for official information.
        </ThemedText>
        <Button 
          mode="outlined" 
          style={styles.button}
          onPress={openIEBCWebsite}
          icon={() => <FontAwesome name="external-link" size={16} />}
        >
          Visit IEBC Website
        </Button>
      </ThemedView>
    </ParallaxScrollView>
  );
}