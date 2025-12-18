"""
CERT Insider Threat Dataset v4.2 Loader

Loads and preprocesses the Carnegie Mellon CERT dataset for training
LSTM/ConvLSTM anomaly detection models.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class CERTDataLoader:
    """
    Loader for CERT Insider Threat Dataset v4.2.
    
    Dataset contains ~1000 users, 500 days of activity, and 70 insider threat scenarios.
    Files include: logon.csv, email.csv, device.csv, http.csv, file.csv
    """
    
    EVENT_TYPES = [
        "logon", "logoff", "email", "http", "file_open", "file_write",
        "device_connect", "device_disconnect", "www_job", "www_news",
        "www_tech", "www_social", "www_other"
    ]
    
    def __init__(self, data_dir: str = "data/cert"):
        """
        Initialize CERT data loader.
        
        Args:
            data_dir: Directory containing CERT CSV files
        """
        self.data_dir = Path(data_dir)
        self.event_type_map = {event: idx for idx, event in enumerate(self.EVENT_TYPES)}
        
        if not self.data_dir.exists():
            logger.warning(f"CERT data directory not found: {self.data_dir}")
            logger.info("Please download CERT v4.2 dataset from:")
            logger.info("https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247")
    
    def load_all_logs(self) -> Dict[str, pd.DataFrame]:
        """
        Load all CERT log files.
        
        Returns:
            Dictionary mapping log type to DataFrame
        """
        logs = {}
        
        log_files = {
            'logon': 'logon.csv',
            'email': 'email.csv',
            'device': 'device.csv',
            'http': 'http.csv',
            'file': 'file.csv'
        }
        
        for log_type, filename in log_files.items():
            filepath = self.data_dir / filename
            if filepath.exists():
                try:
                    logs[log_type] = pd.read_csv(filepath)
                    logger.info(f"Loaded {log_type}: {len(logs[log_type])} records")
                except Exception as e:
                    logger.error(f"Error loading {filename}: {e}")
            else:
                logger.warning(f"File not found: {filepath}")
        
        return logs
    
    def load_user_info(self) -> Optional[pd.DataFrame]:
        """
        Load user information including roles.
        
        Returns:
            DataFrame with user metadata or None if not found
        """
        filepath = self.data_dir / 'LDAP' / '2010-01.csv'
        
        if not filepath.exists():
            # Try alternative location
            filepath = self.data_dir / 'ldap.csv'
        
        if filepath.exists():
            try:
                df = pd.read_csv(filepath)
                logger.info(f"Loaded user info: {len(df)} users")
                return df
            except Exception as e:
                logger.error(f"Error loading user info: {e}")
        
        return None
    
    def load_insider_scenarios(self) -> Optional[pd.DataFrame]:
        """
        Load ground truth insider threat scenarios.
        
        Returns:
            DataFrame with insider threat labels or None if not found
        """
        filepath = self.data_dir / 'insiders.csv'
        
        if filepath.exists():
            try:
                df = pd.read_csv(filepath)
                logger.info(f"Loaded insider scenarios: {len(df)} threats")
                return df
            except Exception as e:
                logger.error(f"Error loading insider scenarios: {e}")
        
        return None
    
    def merge_logs_by_user(
        self,
        logs: Dict[str, pd.DataFrame],
        user_id: str
    ) -> pd.DataFrame:
        """
        Merge all log types for a specific user into chronological order.
        
        Args:
            logs: Dictionary of log DataFrames
            user_id: User identifier
        
        Returns:
            Merged DataFrame sorted by timestamp
        """
        user_events = []
        
        # Process logon logs
        if 'logon' in logs:
            logon_df = logs['logon'][logs['logon']['user'] == user_id].copy()
            logon_df['event_type'] = logon_df['activity'].apply(
                lambda x: 'logon' if x == 'Logon' else 'logoff'
            )
            logon_df['timestamp'] = pd.to_datetime(logon_df['date'])
            user_events.append(logon_df[['timestamp', 'event_type', 'date']])
        
        # Process email logs
        if 'email' in logs:
            email_df = logs['email'][logs['email']['user'] == user_id].copy()
            email_df['event_type'] = 'email'
            email_df['timestamp'] = pd.to_datetime(email_df['date'])
            user_events.append(email_df[['timestamp', 'event_type', 'date']])
        
        # Process device logs
        if 'device' in logs:
            device_df = logs['device'][logs['device']['user'] == user_id].copy()
            device_df['event_type'] = device_df['activity'].apply(
                lambda x: 'device_connect' if x == 'Connect' else 'device_disconnect'
            )
            device_df['timestamp'] = pd.to_datetime(device_df['date'])
            user_events.append(device_df[['timestamp', 'event_type', 'date']])
        
        # Process http logs
        if 'http' in logs:
            http_df = logs['http'][logs['http']['user'] == user_id].copy()
            http_df['event_type'] = 'http'
            http_df['timestamp'] = pd.to_datetime(http_df['date'])
            user_events.append(http_df[['timestamp', 'event_type', 'date']])
        
        # Process file logs
        if 'file' in logs:
            file_df = logs['file'][logs['file']['user'] == user_id].copy()
            file_df['event_type'] = 'file_open'
            file_df['timestamp'] = pd.to_datetime(file_df['date'])
            user_events.append(file_df[['timestamp', 'event_type', 'date']])
        
        # Merge and sort
        if user_events:
            merged = pd.concat(user_events, ignore_index=True)
            merged = merged.sort_values('timestamp')
            return merged
        
        return pd.DataFrame()
    
    def get_user_list(self, logs: Dict[str, pd.DataFrame]) -> List[str]:
        """
        Get list of all users in the dataset.
        
        Args:
            logs: Dictionary of log DataFrames
        
        Returns:
            List of unique user IDs
        """
        users = set()
        
        for log_type, df in logs.items():
            if 'user' in df.columns:
                users.update(df['user'].unique())
        
        return sorted(list(users))
