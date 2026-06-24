from mahjong.hand_calculating.hand import HandCalculator
from mahjong.tile import TilesConverter
from mahjong.hand_calculating.hand_config import HandConfig

# 計算機
calculator = HandCalculator()

# 手牌（萬子・筒子・索子）
tiles = TilesConverter.string_to_136_array(
    man='233445',
    pin='567',
    sou='22678'
)

# 上がり牌（5万）
win_tile = TilesConverter.string_to_136_array(man='5')[0]

# 上がり条件（ツモ）
config = HandConfig(is_tsumo=True)

# 点数計算
result = calculator.estimate_hand_value(tiles, win_tile, config=config)

# 結果出力
print('🀄 役:', result.yaku)
print('🎯 翻数:', result.han)
print('💰 点数:', result.cost['main'] if result.cost else '計算できず')