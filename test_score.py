from mahjong.hand_calculating.hand import HandCalculator
from mahjong.tile import TilesConverter
from mahjong.hand_calculating.hand_config import HandConfig

calculator = HandCalculator()

tiles = TilesConverter.string_to_136_array(
    man='234',
    pin='567',
    sou='678',
    honors='5555'
)
win_tile = TilesConverter.string_to_136_array(sou='6')[0]

config = HandConfig(is_tsumo=True)

result = calculator.estimate_hand_value(tiles, win_tile, config=config)

print('🀄 役:', result.yaku)
print('🎯 翻数:', result.han)
print('💰 点数:', result.cost['main'] if result.cost else '計算できず')