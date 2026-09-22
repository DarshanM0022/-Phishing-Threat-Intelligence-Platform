import json
import numpy as np
from typing import List, Dict, Any, Optional, Tuple

class TreeNode:
    def __init__(
        self,
        feature_idx: Optional[int] = None,
        threshold: Optional[float] = None,
        left: Optional['TreeNode'] = None,
        right: Optional['TreeNode'] = None,
        value: Optional[float] = None,
        prob: float = 0.5,
        samples: int = 0
    ):
        self.feature_idx = feature_idx
        self.threshold = threshold
        self.left = left
        self.right = right
        self.value = value  # Leaf probability
        self.prob = prob    # Subtree probability of phishing
        self.samples = samples

    @property
    def is_leaf(self) -> bool:
        return self.value is not None

    def to_dict(self) -> Dict[str, Any]:
        if self.is_leaf:
            return {
                "value": float(self.value) if self.value is not None else 0.5,
                "prob": float(self.prob),
                "samples": int(self.samples)
            }
        return {
            "feature_idx": int(self.feature_idx) if self.feature_idx is not None else None,
            "threshold": float(self.threshold) if self.threshold is not None else None,
            "prob": float(self.prob),
            "samples": int(self.samples),
            "left": self.left.to_dict() if self.left else None,
            "right": self.right.to_dict() if self.right else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'TreeNode':
        if "value" in d and d["value"] is not None:
            return cls(
                value=d["value"],
                prob=d.get("prob", d["value"]),
                samples=d.get("samples", 0)
            )
        return cls(
            feature_idx=d.get("feature_idx"),
            threshold=d.get("threshold"),
            prob=d.get("prob", 0.5),
            samples=d.get("samples", 0),
            left=cls.from_dict(d["left"]) if d.get("left") else None,
            right=cls.from_dict(d["right"]) if d.get("right") else None,
        )

class DecisionTree:
    def __init__(self, max_depth: int = 8, min_samples_split: int = 4, max_features: Optional[int] = None):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.max_features = max_features
        self.root: Optional[TreeNode] = None

    def _gini(self, y: np.ndarray) -> float:
        if len(y) == 0:
            return 0.0
        p1 = np.mean(y)
        p0 = 1.0 - p1
        return 1.0 - (p0**2 + p1**2)

    def _best_split(self, X: np.ndarray, y: np.ndarray) -> Tuple[Optional[int], Optional[float], float]:
        n_samples, n_features = X.shape
        if n_samples < self.min_samples_split:
            return None, None, 0.0

        current_gini = self._gini(y)
        best_gain = 0.0
        best_feat = None
        best_thresh = None

        feature_indices = np.arange(n_features)
        if self.max_features and self.max_features < n_features:
            feature_indices = np.random.choice(n_features, self.max_features, replace=False)

        for f_idx in feature_indices:
            values = X[:, f_idx]
            unique_vals = np.unique(values)
            if len(unique_vals) <= 1:
                continue

            if len(unique_vals) > 10:
                thresholds = np.percentile(unique_vals, np.linspace(10, 90, 8))
            else:
                thresholds = (unique_vals[:-1] + unique_vals[1:]) / 2.0

            for thresh in thresholds:
                left_mask = values <= thresh
                right_mask = ~left_mask
                if np.sum(left_mask) == 0 or np.sum(right_mask) == 0:
                    continue

                gini_left = self._gini(y[left_mask])
                gini_right = self._gini(y[right_mask])
                w_left = np.sum(left_mask) / n_samples
                w_right = np.sum(right_mask) / n_samples
                gain = current_gini - (w_left * gini_left + w_right * gini_right)

                if gain > best_gain:
                    best_gain = gain
                    best_feat = f_idx
                    best_thresh = float(thresh)

        return best_feat, best_thresh, best_gain

    def _build_tree(self, X: np.ndarray, y: np.ndarray, depth: int = 0) -> TreeNode:
        n_samples = len(y)
        prob = float(np.mean(y)) if n_samples > 0 else 0.0

        if depth >= self.max_depth or n_samples < self.min_samples_split or len(np.unique(y)) <= 1:
            return TreeNode(value=prob, prob=prob, samples=n_samples)

        feat_idx, thresh, gain = self._best_split(X, y)
        if feat_idx is None or gain <= 1e-5:
            return TreeNode(value=prob, prob=prob, samples=n_samples)

        left_mask = X[:, feat_idx] <= thresh
        right_mask = ~left_mask

        left_child = self._build_tree(X[left_mask], y[left_mask], depth + 1)
        right_child = self._build_tree(X[right_mask], y[right_mask], depth + 1)

        return TreeNode(
            feature_idx=feat_idx,
            threshold=thresh,
            prob=prob,
            left=left_child,
            right=right_child,
            samples=n_samples
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.root = self._build_tree(X, y, depth=0)

    def predict_proba_single(self, x: np.ndarray) -> float:
        node = self.root
        while node and not node.is_leaf:
            if x[node.feature_idx] <= node.threshold:
                node = node.left
            else:
                node = node.right
        return node.value if node else 0.5

    def explain_single(self, x: np.ndarray, n_features: int) -> np.ndarray:
        """
        Computes exact local TreeSHAP / Saabas feature contributions along traversal path.
        """
        contributions = np.zeros(n_features)
        node = self.root
        if not node:
            return contributions

        current_prob = node.prob
        while node and not node.is_leaf:
            feat_idx = node.feature_idx
            next_node = node.left if x[feat_idx] <= node.threshold else node.right
            delta = next_node.prob - current_prob
            contributions[feat_idx] += delta
            current_prob = next_node.prob
            node = next_node

        return contributions

class PureRandomForest:
    def __init__(self, n_estimators: int = 50, max_depth: int = 8, min_samples_split: int = 4):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.trees: List[DecisionTree] = []
        self.n_features: int = 0

    def fit(self, X: np.ndarray, y: np.ndarray):
        n_samples, self.n_features = X.shape
        max_features = int(np.sqrt(self.n_features)) + 1
        self.trees = []

        for _ in range(self.n_estimators):
            boot_indices = np.random.choice(n_samples, n_samples, replace=True)
            X_boot = X[boot_indices]
            y_boot = y[boot_indices]

            tree = DecisionTree(
                max_depth=self.max_depth,
                min_samples_split=self.min_samples_split,
                max_features=max_features
            )
            tree.fit(X_boot, y_boot)
            self.trees.append(tree)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        probs = np.zeros((X.shape[0], 2))
        for tree in self.trees:
            for i in range(X.shape[0]):
                p1 = tree.predict_proba_single(X[i])
                probs[i, 1] += p1
        probs[:, 1] /= len(self.trees)
        probs[:, 0] = 1.0 - probs[:, 1]
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs[:, 1] >= 0.5).astype(int)

    def explain_instance(self, x: np.ndarray) -> np.ndarray:
        total_contributions = np.zeros(self.n_features)
        for tree in self.trees:
            total_contributions += tree.explain_single(x, self.n_features)
        return total_contributions / len(self.trees)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "n_features": self.n_features,
            "trees": [t.root.to_dict() for t in self.trees if t.root is not None]
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PureRandomForest':
        rf = cls(
            n_estimators=d.get("n_estimators", 50),
            max_depth=d.get("max_depth", 8)
        )
        rf.n_features = d.get("n_features", 27)
        rf.trees = []
        for t_dict in d.get("trees", []):
            dt = DecisionTree(max_depth=rf.max_depth)
            dt.root = TreeNode.from_dict(t_dict)
            rf.trees.append(dt)
        return rf
