"""
Training Script for LSTM/ConvLSTM Anomaly Detection Models

Trains models on CERT Insider Threat Dataset v4.2
Following methodology from Tian et al. (2020)
"""

import sys
from pathlib import Path

# Add server to path
server_root = Path(__file__).parent.parent
sys.path.insert(0, str(server_root / "src"))

import logging
import argparse
from server.ml.train import ModelTrainer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main training script."""
    parser = argparse.ArgumentParser(
        description='Train LSTM/ConvLSTM anomaly detection models'
    )
    parser.add_argument(
        '--data-dir',
        type=str,
        default='data/cert',
        help='Directory containing CERT dataset'
    )
    parser.add_argument(
        '--model-dir',
        type=str,
        default='data/models/lstm_convlstm',
        help='Directory to save trained models'
    )
    parser.add_argument(
        '--max-users',
        type=int,
        default=10,
        help='Maximum number of users to train (default: 10)'
    )
    parser.add_argument(
        '--epochs',
        type=int,
        default=40,
        help='Number of training epochs (default: 40)'
    )
    parser.add_argument(
        '--reports-dir',
        type=str,
        default='reports',
        help='Directory to save training reports'
    )
    
    args = parser.parse_args()
    
    logger.info("="*60)
    logger.info("LSTM/ConvLSTM Anomaly Detection Model Training")
    logger.info("="*60)
    logger.info(f"Data directory: {args.data_dir}")
    logger.info(f"Model directory: {args.model_dir}")
    logger.info(f"Max users: {args.max_users}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info("="*60)
    
    # Check if CERT data exists
    data_path = Path(args.data_dir)
    if not data_path.exists():
        logger.error(f"Data directory not found: {data_path}")
        logger.info("\nPlease download CERT v4.2 dataset from:")
        logger.info("https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247")
        logger.info("or")
        logger.info("https://www.kaggle.com/datasets/nitishabharathi/cert-insider-threat")
        logger.info(f"\nExtract to: {data_path.absolute()}")
        return 1
    
    # Initialize trainer
    trainer = ModelTrainer(
        data_dir=args.data_dir,
        model_dir=args.model_dir,
        reports_dir=args.reports_dir
    )
    
    # Run training pipeline
    logger.info("\nStarting training pipeline...")
    try:
        report = trainer.train_full_pipeline(
            max_users=args.max_users,
            epochs=args.epochs
        )
        
        logger.info("\n" + "="*60)
        logger.info("Training Complete!")
        logger.info("="*60)
        logger.info(f"Users attempted: {report.get('num_users_attempted', 0)}")
        logger.info(f"Users successful: {report.get('num_users_successful', 0)}")
        logger.info(f"Report saved to: {args.reports_dir}/model_training_report.json")
        logger.info("="*60)
        
        return 0
        
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
