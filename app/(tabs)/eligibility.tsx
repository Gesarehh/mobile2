import { useState } from 'react';
import { StyleSheet, ScrollView, Alert } from 'react-native';
import { ThemedText } from '@/components/ThemedText';
import { ThemedView } from '@/components/ThemedView';
import { TextInput, Button } from 'react-native-paper';
import { FontAwesome } from '@expo/vector-icons';

export default function EligibilityScreen() {
  const [idNumber, setIdNumber] = useState('');
  const [loading, setLoading] = useState(false);

  const checkEligibility = () => {
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      const isEligible = Math.random() > 0.3;
      Alert.alert(
        isEligible ? 'Eligible to Vote' : 'Not Eligible',
        isEligible
          ? 'You are registered to vote in the next election!'
          : 'Please verify your details or register as a voter.'
      );
    }, 1500);
  };

  return (
    <ScrollView 
      contentContainerStyle={styles.container}
      style={styles.scrollView}
    >
      <ThemedView style={styles.content}>
        <ThemedText type="title" style={styles.titleText}>Voter Eligibility Check</ThemedText>
        
        <TextInput
          label="ID Number/Passport"
          value={idNumber}
          onChangeText={setIdNumber}
          style={styles.input}
          keyboardType="numeric"
          left={<TextInput.Icon icon="card-account-details" color="white" />}
          theme={{
            colors: {
              text: 'white',
              primary: 'white',
              placeholder: 'white',
              background: 'transparent',
              onSurfaceVariant: 'white'
            }
          }}
          textColor="white"
          underlineColor="white"
          activeUnderlineColor="white"
        />

        <Button
          mode="contained"
          onPress={checkEligibility}
          loading={loading}
          disabled={!idNumber || idNumber.length < 6}
          style={styles.button}
          icon="account-check"
          buttonColor="#2196F3"
          textColor="white"
        >
          Check Status
        </Button>

        <ThemedView style={styles.infoBox}>
          <ThemedText type="defaultSemiBold" style={styles.whiteText}>
            <FontAwesome name="info-circle" size={16} color="white" /> Requirements:
          </ThemedText>
          <ThemedText style={styles.whiteText}>- Must be 18+ years old</ThemedText>
          <ThemedText style={styles.whiteText}>- Kenyan citizen</ThemedText>
          <ThemedText style={styles.whiteText}>- Registered voter</ThemedText>
          <ThemedText style={styles.whiteText}>- Valid ID/Passport</ThemedText>
        </ThemedView>
      </ThemedView>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scrollView: {
    backgroundColor: '#121212', 
  },
  container: {
    flexGrow: 1,
    padding: 16,
    backgroundColor: '#121212', 
  },
  content: {
    gap: 24,
    backgroundColor: '#121212', 
  },
  input: {
    marginTop: 8,
    backgroundColor: 'transparent',
    color: 'white',
    borderBottomColor: 'white',
  },
  button: {
    marginTop: 16,
  },
  infoBox: {
    marginTop: 24,
    padding: 16,
    borderRadius: 8,
    gap: 8,
    backgroundColor: 'rgba(0, 100, 0, 0.2)', 
    borderColor: 'rgba(0, 255, 0, 0.3)',
    borderWidth: 1,
  },
  titleText: {
    color: 'white', 
  },
  whiteText: {
    color: 'white', 
  }
});