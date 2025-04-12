import { StyleSheet, Platform, Linking } from 'react-native';
import { Collapsible } from '@/components/Collapsible';
import { ExternalLink } from '@/components/ExternalLink';
import ParallaxScrollView from '@/components/ParallaxScrollView';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import { Image } from 'expo-image';
import { Button } from 'react-native-paper';
import { FontAwesome } from '@expo/vector-icons';

export default function AboutScreen() {
  const openIEBCWebsite = () => {
    Linking.openURL('https://www.iebc.or.ke');
  };

  return (
    <ParallaxScrollView
      headerBackgroundColor={{ light: '#D0D0D0', dark: '#353636' }}
      headerImage={
        <Image
          source={require('@/assets/images/kenya.jpg')}
          style={styles.headerImage}
          contentFit="contain"
        />
      }>
      <ThemedView style={styles.titleContainer}>
        <ThemedText type="title">About Kenya Voter App</ThemedText>
      </ThemedView>
      
      <ThemedText style={styles.introText}>
        The Kenya Voter App is designed to empower Kenyan citizens with tools for democratic participation.
      </ThemedText>

      <Collapsible title="App Features">
        <ThemedView style={styles.featureItem}>
          <FontAwesome name="check-square" size={16} color="#006400" />
          <ThemedText style={styles.featureText}>Voter eligibility verification</ThemedText>
        </ThemedView>
        <ThemedView style={styles.featureItem}>
          <FontAwesome name="map-marker" size={16} color="#006400" />
          <ThemedText style={styles.featureText}>Polling station locator</ThemedText>
        </ThemedView>
        <ThemedView style={styles.featureItem}>
          <FontAwesome name="calendar" size={16} color="#006400" />
          <ThemedText style={styles.featureText}>Election date reminders</ThemedText>
        </ThemedView>
        <ThemedView style={styles.featureItem}>
          <FontAwesome name="info-circle" size={16} color="#006400" />
          <ThemedText style={styles.featureText}>Voter education resources</ThemedText>
        </ThemedView>
      </Collapsible>

      <Collapsible title="How to Use">
        <ThemedText>
          1. <ThemedText type="defaultSemiBold">Check Eligibility</ThemedText>: Enter your ID number to verify voter registration status.
        </ThemedText>
        <ThemedText>
          2. <ThemedText type="defaultSemiBold">Find Polling Stations</ThemedText>: Use the interactive map to locate your designated voting center.
        </ThemedText>
        <ThemedText>
          3. <ThemedText type="defaultSemiBold">Get Information</ThemedText>: Access official election materials and voter education.
        </ThemedText>
      </Collapsible>

      <Collapsible title="Official Resources">
        <ThemedText>
          This app uses data from the Independent Electoral and Boundaries Commission (IEBC) of Kenya.
        </ThemedText>
        <Button 
          mode="outlined" 
          style={styles.button}
          onPress={openIEBCWebsite}
          icon={() => <FontAwesome name="external-link" size={16} />}
        >
          Visit IEBC Website
        </Button>
      </Collapsible>

      <Collapsible title="About the Developers">
        <ThemedText>
          This app was developed to promote transparent electoral processes in Kenya.
        </ThemedText>
      </Collapsible>

      <Collapsible title="App Version">
        <ThemedText>
          Kenya Voter App {Platform.OS === 'ios' ? 'iOS' : 'Android'} Version 1.0.0
        </ThemedText>
        <ThemedText>
          Last updated: {new Date().toLocaleDateString()}
        </ThemedText>
      </Collapsible>
    </ParallaxScrollView>
  );
}

const styles = StyleSheet.create({
  headerImage: {
    height: "100%",
    width: '100%',
    bottom: 0,
    position: 'absolute',
  },
  titleContainer: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 16,
  },
  introText: {
    marginBottom: 20,
    fontSize: 16,
  },
  featureItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginVertical: 4,
  },
  featureText: {
    fontSize: 15,
  },
  button: {
    marginTop: 12,
    alignSelf: 'flex-start',
  },
});